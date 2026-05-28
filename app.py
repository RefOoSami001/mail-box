import poplib
import email
import os
import functools
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from bson import ObjectId

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

MONGO_URI = os.environ.get(
    "MONGO_URI",
    "mongodb://raafatsamy109:hQm3tZYWWEjNI2WS@ac-phjothd-shard-00-00.jdjy8pd.mongodb.net:27017,"
    "ac-phjothd-shard-00-01.jdjy8pd.mongodb.net:27017,"
    "ac-phjothd-shard-00-02.jdjy8pd.mongodb.net:27017/"
    "?replicaSet=atlas-12rk7b-shard-0&ssl=true&authSource=admin&retryWrites=true&w=majority&appName=Cluster0"
)

DEFAULT_HOST = "pop3.kuku.lu"
DEFAULT_PORT = 995

mongo_client = MongoClient(MONGO_URI)
db = mongo_client.get_default_database("mailbox")
users_col   = db["users"]
filters_col = db["filters"]

users_col.create_index("email", unique=True)


# ─── DB Helpers ──────────────────────────────────────────────────

def get_user_password(email_address):
    doc = users_col.find_one({"email": email_address})
    return doc["password"] if doc else None


def get_active_filters():
    return [f["pattern"] for f in filters_col.find({"enabled": True})]


def subject_passes_filters(subject, patterns):
    if not patterns:
        return True
    for pattern in patterns:
        if pattern.lower() in subject.lower():
            return True
    return False


# ─── Admin Auth ──────────────────────────────────────────────────

def admin_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapper


# ─── Persistent in-memory cache ──────────────────────────────────
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
    existing = _cache.get(username, {"summaries": [], "bodies": {}})
    existing_uids = {m["uid"] for m in existing["summaries"]}

    active_filters = get_active_filters()

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
        filtered = [m for m in existing["summaries"] if subject_passes_filters(m["subject"], active_filters)]
        return filtered

    new_summaries = []
    new_bodies: dict = {}

    for item in reversed(uidl_list):
        if len(new_summaries) + len(existing["summaries"]) >= limit:
            break
        try:
            parts = item.decode(errors="ignore").split(" ", 1)
            if len(parts) < 2:
                continue
            num, uid = parts
            uid = uid.strip()

            if uid in existing_uids:
                continue

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

    merged_summaries = new_summaries + existing["summaries"]
    merged_bodies    = {**existing["bodies"], **new_bodies}

    _cache[username] = {"summaries": merged_summaries, "bodies": merged_bodies}

    filtered = [m for m in merged_summaries if subject_passes_filters(m["subject"], active_filters)]
    return filtered


# ─── User Routes ──────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        host     = request.form.get("host", DEFAULT_HOST).strip() or DEFAULT_HOST
        port     = request.form.get("port", str(DEFAULT_PORT)).strip() or str(DEFAULT_PORT)
        username = request.form.get("username", "").strip()

        if not username:
            error = "الرجاء إدخال البريد الإلكتروني."
        else:
            password = get_user_password(username)
            if password is None:
                error = "هذا البريد الإلكتروني غير موجود في قاعدة البيانات."
            else:
                try:
                    conn = connect_pop3(host, port, username, password)
                    try:
                        fetch_and_merge(conn, username)
                    except Exception:
                        pass
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
        username = session["username"]
        active_filters = get_active_filters()
        cached_summaries = _cache.get(username, {}).get("summaries", [])
        filtered = [m for m in cached_summaries if subject_passes_filters(m["subject"], active_filters)]
        if filtered:
            return jsonify({
                "messages": filtered,
                "total":    len(filtered),
                "warning":  "تعذّر الاتصال بالخادم — يتم عرض الرسائل المحفوظة مسبقاً"
            })
        return jsonify({"error": str(e)}), 500


@app.route("/api/message/<path:uid>")
def api_message(uid):
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


# ─── Admin Routes ─────────────────────────────────────────────────

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            return redirect(url_for("admin_panel"))
        else:
            error = "كلمة المرور غير صحيحة"
    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_panel():
    return render_template("admin.html")


# ── Admin API: Users ──

@app.route("/admin/api/users", methods=["GET"])
@admin_required
def admin_list_users():
    users = list(users_col.find({}, {"_id": 0}))
    return jsonify({"users": users})


@app.route("/admin/api/users", methods=["POST"])
@admin_required
def admin_add_user():
    data = request.json or {}
    em   = (data.get("email") or "").strip().lower()
    pw   = (data.get("password") or "").strip()
    if not em or not pw:
        return jsonify({"error": "email and password required"}), 400
    try:
        users_col.insert_one({"email": em, "password": pw})
        return jsonify({"ok": True})
    except DuplicateKeyError:
        return jsonify({"error": f"Email {em} already exists"}), 409


@app.route("/admin/api/users/<path:email_addr>", methods=["PUT"])
@admin_required
def admin_edit_user(email_addr):
    data = request.json or {}
    new_email = (data.get("email") or "").strip().lower()
    new_pw    = (data.get("password") or "").strip()
    if not new_email or not new_pw:
        return jsonify({"error": "email and password required"}), 400
    update = {"$set": {"email": new_email, "password": new_pw}}
    try:
        result = users_col.update_one({"email": email_addr}, update)
        if result.matched_count == 0:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"ok": True})
    except DuplicateKeyError:
        return jsonify({"error": f"Email {new_email} already exists"}), 409


@app.route("/admin/api/users/<path:email_addr>", methods=["DELETE"])
@admin_required
def admin_delete_user(email_addr):
    result = users_col.delete_one({"email": email_addr})
    if result.deleted_count == 0:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"ok": True})


@app.route("/admin/api/users/bulk", methods=["POST"])
@admin_required
def admin_bulk_users():
    data = request.json or {}
    raw  = (data.get("text") or "").strip()
    mode = (data.get("mode") or "skip").strip()

    if not raw:
        return jsonify({"error": "No text provided"}), 400

    added = skipped = errors = 0
    error_list = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            error_list.append(f"Bad format (no colon): {line[:60]}")
            errors += 1
            continue
        parts = line.split(":", 1)
        em = parts[0].strip().lower()
        pw = parts[1].strip()
        if not em or not pw:
            error_list.append(f"Empty field: {line[:60]}")
            errors += 1
            continue
        try:
            if mode == "overwrite":
                users_col.update_one(
                    {"email": em},
                    {"$set": {"email": em, "password": pw}},
                    upsert=True
                )
                added += 1
            else:
                users_col.insert_one({"email": em, "password": pw})
                added += 1
        except DuplicateKeyError:
            skipped += 1
        except Exception as exc:
            error_list.append(f"{em}: {exc}")
            errors += 1

    return jsonify({
        "added": added,
        "skipped": skipped,
        "errors": errors,
        "error_details": error_list[:20]
    })


# ── Admin API: Filters ──

@app.route("/admin/api/filters", methods=["GET"])
@admin_required
def admin_list_filters():
    filters = [
        {"id": str(f["_id"]), "pattern": f["pattern"], "enabled": f.get("enabled", True)}
        for f in filters_col.find({})
    ]
    return jsonify({"filters": filters})


@app.route("/admin/api/filters", methods=["POST"])
@admin_required
def admin_add_filter():
    data    = request.json or {}
    pattern = (data.get("pattern") or "").strip()
    if not pattern:
        return jsonify({"error": "pattern required"}), 400
    result = filters_col.insert_one({"pattern": pattern, "enabled": True})
    return jsonify({"id": str(result.inserted_id), "ok": True})


@app.route("/admin/api/filters/<filter_id>", methods=["DELETE"])
@admin_required
def admin_delete_filter(filter_id):
    try:
        result = filters_col.delete_one({"_id": ObjectId(filter_id)})
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    if result.deleted_count == 0:
        return jsonify({"error": "Filter not found"}), 404
    return jsonify({"ok": True})


@app.route("/admin/api/filters/<filter_id>", methods=["PUT"])
@admin_required
def admin_toggle_filter(filter_id):
    data = request.json or {}
    enabled = bool(data.get("enabled", True))
    try:
        result = filters_col.update_one(
            {"_id": ObjectId(filter_id)},
            {"$set": {"enabled": enabled}}
        )
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    if result.matched_count == 0:
        return jsonify({"error": "Filter not found"}), 404
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
