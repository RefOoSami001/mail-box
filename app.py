import poplib
import email
import os
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, session, redirect, url_for, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

DEFAULT_HOST = "pop3.kuku.lu"
DEFAULT_PORT = 995

# ─── Persistent in-memory cache (survives refresh) ───────────────
# Structure per username:
#   "summaries": [ { uid, num, subject, sender_name, sender_addr, date, preview }, ... ]
#   "bodies":    { uid: { "body": str, "body_type": str } }
_cache: dict = {}


# ─── POP3 Helpers ────────────────────────────────────────────────

def connect_pop3(host, port, user, password):
    conn = poplib.POP3_SSL(host, int(port))
    conn.user(user)
    conn.pass_(password)
    return conn


def decode_str(value, fallback_enc="utf-8"):
    if value is None:
        return ""
    parts = decode_header(value)
    result = []
    for chunk, enc in parts:
        if isinstance(chunk, bytes):
            result.append(chunk.decode(enc or fallback_enc, errors="ignore"))
        else:
            result.append(chunk)
    return "".join(result)


def extract_body(msg):
    """Return (body_text, body_type) preferring HTML, falling back to plain."""
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="ignore")
            if ct == "text/plain" and not plain:
                plain = text
            elif ct == "text/html" and not html:
                html = text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="ignore")
            if msg.get_content_type() == "text/html":
                html = text
            else:
                plain = text

    if html:
        return html, "html"
    if plain:
        return plain, "plain"
    return "(لا يوجد محتوى)", "plain"


def format_date(date_str):
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.strftime("%d %b %Y  %H:%M")
    except Exception:
        return date_str or "—"


def preview_from_msg(msg):
    """Short plain-text preview from any message."""
    preview = ""
    for part in msg.walk():
        ct = part.get_content_type()
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        charset = part.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="ignore")
        if ct == "text/plain":
            preview = text[:250]
            break
        elif ct == "text/html" and not preview:
            preview = BeautifulSoup(text, "html.parser").get_text()[:250]

    if not preview and not msg.is_multipart():
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            raw_text = payload.decode(charset, errors="ignore")
            preview = (
                BeautifulSoup(raw_text, "html.parser").get_text()[:250]
                if msg.get_content_type() == "text/html"
                else raw_text[:250]
            )
    return preview.strip()


def fetch_and_merge(conn, username, limit=50):
    """
    Fetch messages in ONE POP3 session and MERGE into the existing cache.
    - If the server returns 0 messages (common after first session on some
      servers), the existing cached summaries and bodies are preserved.
    - New UIDs that weren't in the cache are prepended (they're newer).
    - Returns the merged summary list (newest first).
    """
    existing = _cache.get(username, {"summaries": [], "bodies": {}})
    existing_uids = {m["uid"] for m in existing["summaries"]}

    try:
        _, uidl_list, _ = conn.uidl()
    except Exception:
        try:
            _, list_raw, _ = conn.list()
            uidl_list = [
                f"{item.decode().split()[0]} uid{item.decode().split()[0]}".encode()
                for item in list_raw
            ]
        except Exception:
            uidl_list = []

    if not uidl_list:
        # Server returned nothing — return whatever we already have cached
        return existing["summaries"]

    new_summaries = []
    new_bodies: dict = {}

    for item in reversed(uidl_list):          # newest first
        if len(new_summaries) + len(existing["summaries"]) >= limit:
            break
        try:
            parts = item.decode(errors="ignore").split(" ", 1)
            if len(parts) < 2:
                continue
            num, uid = parts
            uid = uid.strip()

            if uid in existing_uids:
                continue                       # already cached — skip fetch

            raw_lines = conn.retr(int(num))[1]
            raw = b"\n".join(raw_lines)
            msg = email.message_from_bytes(raw)

            subject = decode_str(msg.get("Subject", "")) or "(بدون موضوع)"
            sender_raw = msg.get("From", "")
            sender_name, sender_addr = parseaddr(decode_str(sender_raw))
            body, body_type = extract_body(msg)
            preview = preview_from_msg(msg)

            new_summaries.append({
                "uid":         uid,
                "num":         num,
                "subject":     subject,
                "sender_name": sender_name or sender_addr,
                "sender_addr": sender_addr,
                "date":        format_date(msg.get("Date", "")),
                "preview":     preview,
            })
            new_bodies[uid] = {"body": body, "body_type": body_type}

        except Exception:
            continue

    # Merge: new messages first, then existing (newest-first order)
    merged_summaries = new_summaries + existing["summaries"]
    merged_bodies    = {**existing["bodies"], **new_bodies}

    _cache[username] = {"summaries": merged_summaries, "bodies": merged_bodies}
    return merged_summaries


# ─── Routes ──────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        host     = request.form.get("host", DEFAULT_HOST).strip() or DEFAULT_HOST
        port     = request.form.get("port", str(DEFAULT_PORT)).strip() or str(DEFAULT_PORT)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        try:
            conn = connect_pop3(host, port, username, password)
            # ── CRITICAL: fetch all messages in this same session before quit.
            # This POP3 server only reveals messages in the FIRST connection after
            # delivery. If we quit here and reconnect from /api/messages, the server
            # returns 0 messages. So we prime the cache right now.
            try:
                fetch_and_merge(conn, username)
            except Exception:
                pass  # cache priming failed — inbox can still try refresh
            conn.quit()
            session["host"]     = host
            session["port"]     = port
            session["username"] = username
            session["password"] = password
            return redirect(url_for("inbox"))
        except Exception as e:
            error = f"فشل الاتصال: {e}"

    return render_template("login.html", error=error)


@app.route("/inbox")
def inbox():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("inbox.html", username=session["username"])


@app.route("/api/messages")
def api_messages():
    if "username" not in session:
        return jsonify({"error": "غير مسجّل"}), 401
    try:
        conn = connect_pop3(
            session["host"], session["port"],
            session["username"], session["password"]
        )
        messages = fetch_and_merge(conn, session["username"])
        conn.quit()
        return jsonify({"messages": messages, "total": len(messages)})
    except Exception as e:
        # Connection failed entirely — still return whatever is cached
        username = session["username"]
        cached_summaries = _cache.get(username, {}).get("summaries", [])
        if cached_summaries:
            return jsonify({
                "messages": cached_summaries,
                "total":    len(cached_summaries),
                "warning":  "تعذّر الاتصال بالخادم — يتم عرض الرسائل المحفوظة مسبقاً"
            })
        return jsonify({"error": str(e)}), 500


@app.route("/api/message/<path:uid>")
def api_message(uid):
    """Body served from in-memory cache — no second POP3 connection."""
    if "username" not in session:
        return jsonify({"error": "غير مسجّل"}), 401

    uid      = uid.strip()
    username = session["username"]
    bodies   = _cache.get(username, {}).get("bodies", {})

    if not bodies:
        return jsonify({"error": "لم يتم تحميل الرسائل بعد — اضغط تحديث أولاً"}), 404

    cached = bodies.get(uid)
    if not cached:
        return jsonify({"error": "رسالة غير موجودة في الذاكرة المؤقتة"}), 404

    return jsonify(cached)


@app.route("/logout")
def logout():
    username = session.get("username")
    if username and username in _cache:
        del _cache[username]
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
