import poplib
import email as email_lib
import os
import re
import unicodedata
import calendar
import functools
import json
import base64
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from pymongo import MongoClient, DESCENDING
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone

# ─── Google / Gmail OAuth (optional — only needed for Outlook forwarding) ─────
try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import Flow
    from google.auth.transport.requests import Request as GoogleRequest
    from googleapiclient.discovery import build as google_build
    GMAIL_AVAILABLE = True
except ImportError:
    GMAIL_AVAILABLE = False
    Flow = None  # type: ignore

# ─── App ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
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

client_accounts_col   = db["client_accounts"]
email_accounts_col    = db["email_accounts"]
filter_categories_col = db["filter_categories"]
login_activity_col    = db["login_activity"]
app_settings_col      = db["app_settings"]

client_accounts_col.create_index("username", unique=True)
email_accounts_col.create_index("email", unique=True)
login_activity_col.create_index([("client_id", 1), ("timestamp", DESCENDING)])
login_activity_col.create_index([("timestamp", DESCENDING)])

_cache: dict = {}
FETCH_LIMIT = 250

# ─── Gmail / Outlook Configuration (stored in MongoDB) ─────────────
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
GMAIL_SETTINGS_ID = "gmail_oauth"
# Optional one-time migration sources (imported into MongoDB then unused)
_LEGACY_CREDENTIALS_PATH = os.environ.get("GOOGLE_CREDENTIALS_FILE", "credentials.json")
_LEGACY_TOKEN_PATH       = os.environ.get("GOOGLE_TOKEN_FILE", "token.json")


def _gmail_settings_doc():
    return app_settings_col.find_one({"_id": GMAIL_SETTINGS_ID}) or {}


def _gmail_settings_update(**fields):
    fields["updated_at"] = datetime.now(timezone.utc)
    app_settings_col.update_one(
        {"_id": GMAIL_SETTINGS_ID},
        {"$set": fields},
        upsert=True,
    )


def get_stored_credentials_config():
    """Return the Google client secrets dict from MongoDB, or None."""
    doc = _gmail_settings_doc()
    cfg = doc.get("credentials")
    return cfg if isinstance(cfg, dict) else None


def get_stored_token_info():
    """Return the OAuth token dict from MongoDB, or None."""
    doc = _gmail_settings_doc()
    tok = doc.get("token")
    return tok if isinstance(tok, dict) else None


def save_stored_credentials_config(config: dict):
    _gmail_settings_update(credentials=config, token=None, oauth_pending=None)


def save_stored_token_info(token_info: dict):
    _gmail_settings_update(token=token_info, oauth_pending=None)


def clear_stored_token():
    app_settings_col.update_one(
        {"_id": GMAIL_SETTINGS_ID},
        {"$set": {"token": None, "oauth_pending": None, "updated_at": datetime.now(timezone.utc)}},
        upsert=True,
    )


def _gmail_redirect_uri():
    """Loopback redirect required for Desktop OAuth clients (no OOB / copy-paste)."""
    host = (request.host or "127.0.0.1:5000").split("%")[0]
    port = host.split(":")[-1] if ":" in host else str(os.environ.get("PORT", 5000))
    if not str(port).isdigit():
        port = str(os.environ.get("PORT", 5000))
    return f"http://127.0.0.1:{port}/admin/api/gmail-oauth-callback"


def _save_oauth_pending(code_verifier, state, redirect_uri):
    _gmail_settings_update(
        oauth_pending={
            "code_verifier": code_verifier,
            "state": state,
            "redirect_uri": redirect_uri,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )


def _load_oauth_pending():
    pending = _gmail_settings_doc().get("oauth_pending")
    return pending if isinstance(pending, dict) else None


def _clear_oauth_pending():
    app_settings_col.update_one(
        {"_id": GMAIL_SETTINGS_ID},
        {"$set": {"oauth_pending": None, "updated_at": datetime.now(timezone.utc)}},
        upsert=True,
    )


def _build_gmail_flow(redirect_uri):
    client_config = get_stored_credentials_config()
    if not client_config:
        raise RuntimeError("لم يتم حفظ اعتمادات Google في قاعدة البيانات بعد")
    return Flow.from_client_config(
        client_config,
        scopes=GMAIL_SCOPES,
        redirect_uri=redirect_uri,
    )


def _migrate_local_gmail_files_to_mongo():
    """One-time import of legacy credentials.json / token.json into MongoDB."""
    doc = _gmail_settings_doc()
    updates = {}

    if not doc.get("credentials") and os.path.exists(_LEGACY_CREDENTIALS_PATH):
        try:
            with open(_LEGACY_CREDENTIALS_PATH, encoding="utf-8") as f:
                parsed = json.load(f)
            if isinstance(parsed, dict) and ("installed" in parsed or "web" in parsed):
                updates["credentials"] = parsed
        except Exception:
            pass

    if not doc.get("token") and os.path.exists(_LEGACY_TOKEN_PATH):
        try:
            with open(_LEGACY_TOKEN_PATH, encoding="utf-8") as f:
                parsed = json.load(f)
            if isinstance(parsed, dict) and parsed.get("refresh_token"):
                updates["token"] = parsed
        except Exception:
            pass

    if updates:
        updates["updated_at"] = datetime.now(timezone.utc)
        updates["migrated_from_files"] = True
        app_settings_col.update_one(
            {"_id": GMAIL_SETTINGS_ID},
            {"$set": updates},
            upsert=True,
        )


_migrate_local_gmail_files_to_mongo()


# All Microsoft consumer email domains that forward to the shared Gmail inbox
OUTLOOK_DOMAINS = {
    "outlook.com", "outlook.fr", "outlook.de", "outlook.es", "outlook.it",
    "outlook.jp", "outlook.com.br", "outlook.co.uk", "outlook.sa",
    "outlook.com.au", "outlook.at", "outlook.be", "outlook.cl",
    "hotmail.com", "hotmail.co.uk", "hotmail.fr", "hotmail.de",
    "hotmail.es", "hotmail.it", "hotmail.com.br",
    "live.com", "live.co.uk", "live.fr", "live.de", "live.nl",
    "msn.com",
}


def is_outlook_email(email_addr: str) -> bool:
    """Return True if this address belongs to a Microsoft consumer mail domain."""
    domain = email_addr.rsplit("@", 1)[-1].lower() if "@" in email_addr else ""
    return domain in OUTLOOK_DOMAINS or domain.endswith(".outlook.com")


# ─── Helpers ──────────────────────────────────────────────────────

def dt_iso(dt):
    """Serialize a datetime to ISO string, always with UTC timezone info."""
    if not dt:
        return "—"
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def add_one_month(date_str):
    """Return date_str + 1 month as YYYY-MM-DD, or None if date_str is falsy."""
    if not date_str:
        return None
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d")
        month = d.month + 1
        year = d.year
        if month > 12:
            month = 1
            year += 1
        max_day = calendar.monthrange(year, month)[1]
        day = min(d.day, max_day)
        return datetime(year, month, day).strftime("%Y-%m-%d")
    except Exception:
        return date_str


def normalize_assigned_emails(raw_list):
    """Normalize assigned_emails to list of dicts (backward compat with old string format)."""
    result = []
    for item in (raw_list or []):
        if isinstance(item, str):
            result.append({"email": item, "start_date": None, "end_date": None, "assigned_at": None})
        elif isinstance(item, dict) and item.get("email"):
            result.append(item)
    return result


def is_email_expired(item):
    """Return True if the assignment is past its end date."""
    today = datetime.now(timezone.utc).date().isoformat()
    end   = item.get("end_date")
    return bool(end and today > end)


def is_email_active(item):
    """Return True if the assignment is currently valid or scheduled to start."""
    return not is_email_expired(item)


def log_activity(client_id, username, action, ip="—", success=True):
    try:
        login_activity_col.insert_one({
            "client_id": client_id,
            "username":  username,
            "timestamp": datetime.now(timezone.utc),
            "action":    action,
            "ip":        ip,
            "success":   success,
        })
    except Exception:
        pass


def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "—").split(",")[0].strip()


def client_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("client_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapper


# ─── POP3 Helpers ─────────────────────────────────────────────────

def connect_pop3(host, port, user, password):
    conn = poplib.POP3_SSL(host, int(port))
    conn.user(user)
    conn.pass_(password)
    return conn


def decode_str(value):
    """Decode a MIME-encoded email header string with Arabic charset fallbacks."""
    if value is None:
        return ""
    parts = decode_header(value)
    result = []
    for chunk, enc in parts:
        if isinstance(chunk, bytes):
            charset = (enc or "").lower().replace("_", "-").strip()
            if charset:
                try:
                    result.append(chunk.decode(charset, errors="ignore"))
                    continue
                except (LookupError, UnicodeDecodeError):
                    pass
            for fallback in ("cp1256", "iso-8859-6", "utf-8", "latin-1"):
                try:
                    decoded = chunk.decode(fallback, errors="ignore")
                    if decoded.strip():
                        result.append(decoded)
                        break
                except (LookupError, UnicodeDecodeError):
                    continue
            else:
                result.append(chunk.decode("latin-1", errors="replace"))
        else:
            result.append(chunk)
    return "".join(result)


def normalize_text(value):
    """Normalize a text string for reliable comparison (NFKC + invisible chars)."""
    if value is None:
        return ""
    text = str(value)
    text = unicodedata.normalize("NFKC", text)
    _INVISIBLE = (
        "\u00A0\u00AD\u200B\u200C\u200D"
        "\u202F\u2007\u2060\uFEFF"
    )
    for ch in _INVISIBLE:
        text = text.replace(ch, " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_body(msg):
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct  = part.get_content_type()
            cd  = str(part.get("Content-Disposition", ""))
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
    return plain or "(لا يوجد محتوى)", "plain"


def format_date(date_str):
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.strftime("%d %b %Y  %H:%M")
    except Exception:
        return date_str or "—"


def text_preview(msg):
    preview = ""
    for part in msg.walk():
        ct = part.get_content_type()
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        charset = part.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="ignore")
        if ct == "text/plain":
            preview = text[:300]
            break
        elif ct == "text/html" and not preview:
            preview = BeautifulSoup(text, "html.parser").get_text()[:300]
    if not preview and not msg.is_multipart():
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            raw = payload.decode(charset, errors="ignore")
            preview = (
                BeautifulSoup(raw, "html.parser").get_text()[:300]
                if msg.get_content_type() == "text/html"
                else raw[:300]
            )
    return preview.strip()


def _build_summary(msg, uid):
    """Build a summary dict from a parsed email.message.Message object."""
    subject_raw = msg.get("Subject", "")
    subject     = normalize_text(decode_str(subject_raw)) or "(بدون موضوع)"
    sender_raw  = msg.get("From", "")
    sender_name, sender_addr = parseaddr(decode_str(sender_raw))
    body, body_type = extract_body(msg)
    preview     = text_preview(msg)
    msg_ts = None
    try:
        msg_dt = parsedate_to_datetime(msg.get("Date", ""))
        if msg_dt is not None and msg_dt.tzinfo is None:
            msg_dt = msg_dt.replace(tzinfo=timezone.utc)
        msg_ts = msg_dt.isoformat() if msg_dt is not None else None
    except Exception:
        msg_ts = None
    return (
        {
            "uid":         uid,
            "subject":     subject,
            "sender_name": sender_name or sender_addr,
            "sender_addr": sender_addr,
            "date":        format_date(msg.get("Date", "")),
            "timestamp":   msg_ts,
            "preview":     preview,
        },
        {"body": body, "body_type": body_type},
    )


# ─── POP3 Fetch ───────────────────────────────────────────────────

def fetch_email_messages(email_addr, pop3_password, pop3_host, pop3_port, limit=FETCH_LIMIT):
    existing   = _cache.get(email_addr, {"summaries": [], "bodies": {}})
    known_uids = {m["uid"] for m in existing["summaries"]}

    conn = connect_pop3(pop3_host, pop3_port, email_addr, pop3_password)
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

    new_summaries: list = []
    new_bodies: dict   = {}

    for item in reversed(uidl_list):
        if len(new_summaries) >= limit:
            break
        try:
            parts = item.decode(errors="ignore").split(" ", 1)
            if len(parts) < 2:
                continue
            num, uid = parts
            uid = uid.strip()
            if uid in known_uids:
                continue

            raw_lines = conn.retr(int(num))[1]
            raw       = b"\n".join(raw_lines)
            msg       = email_lib.message_from_bytes(raw)

            summary, body_entry = _build_summary(msg, uid)
            new_summaries.append(summary)
            new_bodies[uid] = body_entry

        except Exception:
            continue

    conn.quit()

    merged_summaries = new_summaries + existing["summaries"]
    merged_bodies    = {**existing["bodies"], **new_bodies}
    _cache[email_addr] = {"summaries": merged_summaries, "bodies": merged_bodies}
    return merged_summaries


# ─── Gmail / Outlook Fetch ────────────────────────────────────────

def get_gmail_credentials():
    """
    Return valid Google OAuth2 credentials, refreshing automatically if expired.
    Token is loaded from / saved to MongoDB.
    Returns None when no token exists or the library is not installed.
    """
    if not GMAIL_AVAILABLE:
        return None
    token_info = get_stored_token_info()
    if not token_info:
        return None
    try:
        creds = Credentials.from_authorized_user_info(token_info, GMAIL_SCOPES)
    except Exception:
        return None
    if creds and creds.valid:
        return creds
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(GoogleRequest())
            save_stored_token_info(json.loads(creds.to_json()))
            return creds
        except Exception:
            return None
    return None


def fetch_outlook_via_gmail(outlook_email: str, limit: int = FETCH_LIMIT) -> list:
    """
    Fetch emails addressed to a specific Outlook inbox using the Gmail API.
    All Outlook inboxes forward to one shared Gmail account; we isolate each
    inbox by searching the To: header for the original Outlook address.
    Uses the same in-memory cache structure as fetch_email_messages().
    """
    cache_key  = f"__gmail__{outlook_email}"
    existing   = _cache.get(cache_key, {"summaries": [], "bodies": {}})
    known_uids = {m["uid"] for m in existing["summaries"]}

    creds = get_gmail_credentials()
    if not creds:
        raise RuntimeError(
            "Gmail OAuth غير مكوّن أو انتهت صلاحية التوكن. "
            "يرجى إعداد Gmail من لوحة الإدارة ← إعدادات Gmail."
        )

    service = google_build("gmail", "v1", credentials=creds, cache_discovery=False)

    # Search only for messages whose To: header contains this Outlook address
    response = service.users().messages().list(
        userId="me",
        q=f"to:{outlook_email}",
        maxResults=limit,
    ).execute()

    new_summaries: list = []
    new_bodies:    dict = {}

    for meta in response.get("messages", []):
        if len(new_summaries) >= limit:
            break
        msg_id = meta["id"]
        if msg_id in known_uids:
            continue
        try:
            msg_data  = service.users().messages().get(
                userId="me", id=msg_id, format="raw"
            ).execute()
            # Gmail API pads base64 inconsistently — add == to be safe
            raw_bytes = base64.urlsafe_b64decode(msg_data["raw"] + "==")
            msg       = email_lib.message_from_bytes(raw_bytes)

            summary, body_entry = _build_summary(msg, msg_id)
            new_summaries.append(summary)
            new_bodies[msg_id] = body_entry

        except Exception as exc:
            print(f"[GMAIL] failed to fetch message {msg_id}: {exc}")
            continue

    merged_summaries = new_summaries + existing["summaries"]
    merged_bodies    = {**existing["bodies"], **new_bodies}
    _cache[cache_key] = {"summaries": merged_summaries, "bodies": merged_bodies}
    return merged_summaries


# ─── Client Routes ────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("client_id"):
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            error = "أدخل اسم المستخدم وكلمة المرور"
        else:
            doc = client_accounts_col.find_one({"username": username})
            if not doc:
                error = "اسم المستخدم غير موجود"
                log_activity(None, username, "login_failed_no_user", get_client_ip(), False)
            elif doc.get("status") == "suspended":
                error = "تم تعليق هذا الحساب. تواصل مع المشرف."
                log_activity(str(doc["_id"]), username, "login_blocked_suspended", get_client_ip(), False)
            elif not check_password_hash(doc["password_hash"], password):
                error = "كلمة المرور غير صحيحة"
                log_activity(str(doc["_id"]), username, "login_failed_bad_pw", get_client_ip(), False)
            else:
                session.permanent = True
                session["client_id"]      = str(doc["_id"])
                session["client_username"]= doc["username"]
                session["client_display"] = doc.get("display_name") or doc["username"]
                client_accounts_col.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"last_login": datetime.now(timezone.utc)}, "$inc": {"login_count": 1}}
                )
                log_activity(str(doc["_id"]), username, "login_success", get_client_ip(), True)
                return redirect(url_for("dashboard"))
    return render_template("login.html", error=error)


@app.route("/dashboard")
@client_required
def dashboard():
    return render_template("dashboard.html",
                           username=session["client_username"],
                           display=session["client_display"])


@app.route("/logout")
def logout():
    cid  = session.get("client_id")
    user = session.get("client_username", "—")
    if cid:
        log_activity(cid, user, "logout", get_client_ip())
    session.pop("client_id", None)
    session.pop("client_username", None)
    session.pop("client_display", None)
    return redirect(url_for("login"))


# ─── Client API ───────────────────────────────────────────────────

@app.route("/api/categories")
@client_required
def api_categories():
    client_doc = client_accounts_col.find_one(
        {"_id": ObjectId(session["client_id"])}, {"allowed_categories": 1}
    )
    allowed = client_doc.get("allowed_categories", []) if client_doc else []
    query = {"enabled": True}
    if allowed:
        try:
            query["_id"] = {"$in": [ObjectId(cid) for cid in allowed]}
        except Exception:
            pass
    cats = [
        {"id": str(c["_id"]), "label": c["label"], "description": c.get("description", "")}
        for c in filter_categories_col.find(query).sort("order", 1)
    ]
    return jsonify({"categories": cats})


@app.route("/api/my-emails")
@client_required
def api_my_emails():
    """Return ALL emails assigned to the client, with an 'expired' flag."""
    doc = client_accounts_col.find_one({"_id": ObjectId(session["client_id"])})
    if not doc:
        return jsonify({"emails": []})
    assigned = normalize_assigned_emails(doc.get("assigned_emails", []))
    result = []
    for item in assigned:
        em = item["email"]
        active = is_email_active(item)
        result.append({
            "email":      em,
            "start_date": item.get("start_date"),
            "end_date":   item.get("end_date"),
            "expired":    not active,
        })
    return jsonify({"emails": result})


@app.route("/api/fetch", methods=["POST"])
@client_required
def api_fetch():
    data        = request.json or {}
    email_addr  = (data.get("email") or "").strip().lower()
    category_id = (data.get("category_id") or "").strip()

    if not email_addr:
        return jsonify({"error": "أدخل البريد الإلكتروني"}), 400

    acc = email_accounts_col.find_one({"email": email_addr})
    if not acc:
        return jsonify({"error": "هذا البريد غير مسجّل في النظام. تواصل مع المشرف."}), 404

    # ── Filter patterns ──────────────────────────────────────────
    patterns = []
    normalized_patterns = []
    category_label = "الكل"
    if category_id:
        try:
            cat = filter_categories_col.find_one({"_id": ObjectId(category_id)})
            if cat:
                patterns            = cat.get("patterns", [])
                normalized_patterns = [normalize_text(p) for p in patterns if p is not None]
                category_label      = cat["label"]
        except Exception:
            pass

    print(f"[FILTER DEBUG] email={email_addr!r}  category={category_label!r}")
    print(f"[FILTER DEBUG] normalized patterns ({len(normalized_patterns)}): {normalized_patterns!r}")

    def apply_filter_patterns(msg_list, patterns_list):
        if not patterns_list:
            return msg_list
        filtered = []
        for m in msg_list:
            subject_lower = normalize_text(m.get("subject", "")).lower()
            if any(p.lower() in subject_lower for p in patterns_list):
                filtered.append(m)
        return filtered

    def apply_time_cutoff(msg_list, cutoff_dt):
        result = []
        for m in msg_list:
            ts = m.get("timestamp")
            if ts is None:
                result.append(m)
                continue
            try:
                msg_dt = datetime.fromisoformat(ts)
                if msg_dt.tzinfo is None:
                    msg_dt = msg_dt.replace(tzinfo=timezone.utc)
                if msg_dt >= cutoff_dt:
                    result.append(m)
            except Exception:
                result.append(m)
        return result

    cutoff_minutes = int(os.environ.get("EMAIL_CUTOFF_MINUTES", 20))
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=cutoff_minutes)

    # ── Route: Outlook → Gmail API  |  Other → POP3 ──────────────
    use_gmail   = (acc.get("account_type") == "gmail_forwarded") or is_outlook_email(email_addr)
    cache_key   = f"__gmail__{email_addr}" if use_gmail else email_addr
    warning     = None

    try:
        if use_gmail:
            summaries = fetch_outlook_via_gmail(email_addr)
        else:
            summaries = fetch_email_messages(
                email_addr,
                acc["pop3_password"],
                acc.get("pop3_host", DEFAULT_HOST),
                acc.get("pop3_port", DEFAULT_PORT),
            )
    except Exception as e:
        cached = _cache.get(cache_key, {}).get("summaries", [])
        if not cached:
            return jsonify({"error": f"فشل جلب الرسائل: {str(e)[:180]}"}), 503
        summaries = cached
        warning   = "تعذّر تحديث الرسائل — يتم عرض نسخة محفوظة مؤقتاً"

    if normalized_patterns:
        summaries = apply_filter_patterns(summaries, normalized_patterns)
    summaries = apply_time_cutoff(summaries, cutoff)
    if summaries:
        summaries = [summaries[0]]

    log_activity(session["client_id"], session["client_username"],
                 f"fetch:{email_addr}:cat:{category_label}", get_client_ip())

    return jsonify({
        "messages":  summaries,
        "total":     len(summaries),
        "warning":   warning,
        "category":  category_label,
        "cached":    warning is not None,
    })


@app.route("/api/message/<uid>")
@client_required
def api_message(uid):
    for cached in _cache.values():
        bodies = cached.get("bodies", {})
        if uid in bodies:
            return jsonify(bodies[uid])
    return jsonify({"error": "الرسالة غير موجودة في الذاكرة المؤقتة"}), 404


# ─── Admin Routes ─────────────────────────────────────────────────

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_panel"))
    error = None
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "").strip()
        if u == ADMIN_USERNAME and p == ADMIN_PASSWORD:
            session.permanent = True
            session["admin_logged_in"] = True
            session["admin_username"]  = u
            return redirect(url_for("admin_panel"))
        error = "بيانات الدخول غير صحيحة"
    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_panel():
    return render_template("admin.html", admin_username=session.get("admin_username", "Admin"))


# ── Admin API: Stats ──────────────────────────────────────────────

@app.route("/admin/api/stats")
@admin_required
def admin_stats():
    total     = client_accounts_col.count_documents({})
    active    = client_accounts_col.count_documents({"status": {"$ne": "suspended"}})
    suspended = client_accounts_col.count_documents({"status": "suspended"})
    emails    = email_accounts_col.count_documents({})
    cats      = filter_categories_col.count_documents({})
    logins_today = login_activity_col.count_documents({
        "timestamp": {"$gte": datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)},
        "action": "login_success"
    })
    return jsonify({
        "total_clients":     total,
        "active_clients":    active,
        "suspended_clients": suspended,
        "email_accounts":    emails,
        "filter_categories": cats,
        "logins_today":      logins_today,
    })


# ── Admin API: Client Accounts ────────────────────────────────────

@app.route("/admin/api/clients")
@admin_required
def admin_list_clients():
    clients = []
    for doc in client_accounts_col.find({}).sort("created_at", DESCENDING):
        assigned = normalize_assigned_emails(doc.get("assigned_emails", []))
        clients.append({
            "id":              str(doc["_id"]),
            "username":        doc["username"],
            "display_name":    doc.get("display_name", ""),
            "status":          doc.get("status", "active"),
            "created_at":      dt_iso(doc.get("created_at")),
            "last_login":      dt_iso(doc.get("last_login")) if doc.get("last_login") else "—",
            "login_count":     doc.get("login_count", 0),
            "assigned_emails": assigned,
            "email_count":          len(assigned),
            "allowed_categories":   doc.get("allowed_categories", []),
        })
    return jsonify({"clients": clients})


@app.route("/admin/api/clients", methods=["POST"])
@admin_required
def admin_create_client():
    data     = request.json or {}
    username = (data.get("username") or "").strip().lower()
    password = (data.get("password") or "").strip()
    display  = (data.get("display_name") or username).strip()
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    try:
        result = client_accounts_col.insert_one({
            "username":        username,
            "display_name":    display,
            "password_hash":   generate_password_hash(password),
            "status":          "active",
            "created_at":      datetime.now(timezone.utc),
            "created_by":      session.get("admin_username", "admin"),
            "last_login":      None,
            "login_count":     0,
            "assigned_emails": [],
        })
        return jsonify({"ok": True, "id": str(result.inserted_id)})
    except DuplicateKeyError:
        return jsonify({"error": f"اسم المستخدم '{username}' مستخدم مسبقاً"}), 409


@app.route("/admin/api/clients/<client_id>", methods=["PUT"])
@admin_required
def admin_edit_client(client_id):
    data   = request.json or {}
    update = {}
    if data.get("username"):
        update["username"] = data["username"].strip().lower()
    if "display_name" in data:
        update["display_name"] = data["display_name"].strip()
    if data.get("password"):
        update["password_hash"] = generate_password_hash(data["password"].strip())
    if data.get("status") in ("active", "suspended"):
        update["status"] = data["status"]
    if not update:
        return jsonify({"error": "nothing to update"}), 400
    try:
        result = client_accounts_col.update_one({"_id": ObjectId(client_id)}, {"$set": update})
    except DuplicateKeyError:
        return jsonify({"error": "اسم المستخدم مستخدم مسبقاً"}), 409
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    if result.matched_count == 0:
        return jsonify({"error": "Client not found"}), 404
    return jsonify({"ok": True})


@app.route("/admin/api/clients/<client_id>", methods=["DELETE"])
@admin_required
def admin_delete_client(client_id):
    try:
        oid = ObjectId(client_id)
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    client_accounts_col.delete_one({"_id": oid})
    login_activity_col.delete_many({"client_id": client_id})
    return jsonify({"ok": True})


@app.route("/admin/api/clients/bulk", methods=["POST"])
@admin_required
def admin_bulk_clients():
    data  = request.json or {}
    raw   = (data.get("text") or "").strip()
    if not raw:
        return jsonify({"error": "No text provided"}), 400
    added = skipped = errors = 0
    error_list = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            error_list.append(f"تنسيق خاطئ: {line[:50]}")
            errors += 1
            continue
        parts    = line.split(":", 1)
        username = parts[0].strip().lower()
        password = parts[1].strip()
        if not username or not password:
            error_list.append(f"حقل فارغ: {line[:50]}")
            errors += 1
            continue
        try:
            client_accounts_col.insert_one({
                "username":        username,
                "display_name":    username,
                "password_hash":   generate_password_hash(password),
                "status":          "active",
                "created_at":      datetime.now(timezone.utc),
                "created_by":      session.get("admin_username", "admin"),
                "last_login":      None,
                "login_count":     0,
                "assigned_emails": [],
            })
            added += 1
        except DuplicateKeyError:
            skipped += 1
        except Exception as exc:
            error_list.append(f"{username}: {exc}")
            errors += 1
    return jsonify({"added": added, "skipped": skipped, "errors": errors, "error_details": error_list[:20]})


@app.route("/admin/api/clients/<client_id>/activity")
@admin_required
def admin_client_activity(client_id):
    logs = list(login_activity_col.find(
        {"client_id": client_id}, {"_id": 0}
    ).sort("timestamp", DESCENDING).limit(30))
    for l in logs:
        if l.get("timestamp"):
            l["timestamp"] = dt_iso(l["timestamp"])
    return jsonify({"activity": logs})


# ── Admin API: Client Email Assignments ───────────────────────────

@app.route("/admin/api/clients/<client_id>/emails", methods=["GET"])
@admin_required
def admin_get_client_emails(client_id):
    try:
        doc = client_accounts_col.find_one({"_id": ObjectId(client_id)})
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    if not doc:
        return jsonify({"error": "Client not found"}), 404
    assigned = normalize_assigned_emails(doc.get("assigned_emails", []))
    return jsonify({"emails": assigned})


@app.route("/admin/api/clients/<client_id>/emails", methods=["POST"])
@admin_required
def admin_assign_client_email(client_id):
    data       = request.json or {}
    email      = (data.get("email") or "").strip().lower()
    start_date = (data.get("start_date") or "").strip() or None
    end_date   = (data.get("end_date") or "").strip() or None
    if not email:
        return jsonify({"error": "email required"}), 400
    acc = email_accounts_col.find_one({"email": email})
    if not acc:
        return jsonify({"error": f"البريد '{email}' غير موجود في قائمة حسابات البريد"}), 404
    try:
        doc = client_accounts_col.find_one({"_id": ObjectId(client_id)})
    except Exception:
        return jsonify({"error": "Invalid client id"}), 400
    if not doc:
        return jsonify({"error": "Client not found"}), 404
    assigned = normalize_assigned_emails(doc.get("assigned_emails", []))
    if any(item["email"] == email for item in assigned):
        return jsonify({"error": f"البريد '{email}' مخصص مسبقاً لهذا العميل"}), 409
    assigned.append({
        "email":       email,
        "start_date":  start_date,
        "end_date":    end_date,
        "assigned_at": datetime.now(timezone.utc).isoformat(),
    })
    client_accounts_col.update_one(
        {"_id": ObjectId(client_id)},
        {"$set": {"assigned_emails": assigned}}
    )
    return jsonify({"ok": True})


@app.route("/admin/api/clients/<client_id>/emails/<path:email>", methods=["PUT"])
@admin_required
def admin_edit_client_email_dates(client_id, email):
    data       = request.json or {}
    start_date = (data.get("start_date") or "").strip() or None
    end_date   = (data.get("end_date") or "").strip() or None
    email      = email.strip().lower()
    try:
        doc = client_accounts_col.find_one({"_id": ObjectId(client_id)})
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    if not doc:
        return jsonify({"error": "Client not found"}), 404
    assigned = normalize_assigned_emails(doc.get("assigned_emails", []))
    found = False
    for item in assigned:
        if item["email"] == email:
            item["start_date"] = start_date
            item["end_date"]   = end_date
            found = True
            break
    if not found:
        return jsonify({"error": "Email not assigned to this client"}), 404
    client_accounts_col.update_one(
        {"_id": ObjectId(client_id)},
        {"$set": {"assigned_emails": assigned}}
    )
    return jsonify({"ok": True})


@app.route("/admin/api/clients/<client_id>/emails/<path:email>", methods=["DELETE"])
@admin_required
def admin_remove_client_email(client_id, email):
    email = email.strip().lower()
    try:
        doc = client_accounts_col.find_one({"_id": ObjectId(client_id)})
    except Exception:
        return jsonify({"error": "Invalid client id"}), 400
    if not doc:
        return jsonify({"error": "Client not found"}), 404
    assigned = normalize_assigned_emails(doc.get("assigned_emails", []))
    new_list = [item for item in assigned if item["email"] != email]
    client_accounts_col.update_one(
        {"_id": ObjectId(client_id)},
        {"$set": {"assigned_emails": new_list}}
    )
    return jsonify({"ok": True})


@app.route("/admin/api/clients/<client_id>/emails/renew-all", methods=["POST"])
@admin_required
def admin_renew_all_client_emails(client_id):
    try:
        doc = client_accounts_col.find_one({"_id": ObjectId(client_id)})
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    if not doc:
        return jsonify({"error": "Client not found"}), 404
    assigned = normalize_assigned_emails(doc.get("assigned_emails", []))
    updated = 0
    for item in assigned:
        end = item.get("end_date")
        if not end:
            continue
        item["start_date"] = end
        item["end_date"]   = add_one_month(end)
        updated += 1
    client_accounts_col.update_one(
        {"_id": ObjectId(client_id)},
        {"$set": {"assigned_emails": assigned}}
    )
    return jsonify({"ok": True, "updated": updated})


# ── Admin API: Email Accounts ─────────────────────────────────────

@app.route("/admin/api/email-accounts")
@admin_required
def admin_list_emails():
    accounts = list(email_accounts_col.find({}, {"pop3_password": 0}).sort("added_at", DESCENDING))
    for a in accounts:
        a["_id"]         = str(a["_id"])
        a["added_at"]    = dt_iso(a.get("added_at")) if a.get("added_at") else ""
        a["account_type"]= a.get("account_type", "pop3")
    return jsonify({"accounts": accounts})


@app.route("/admin/api/email-accounts/assignment-status")
@admin_required
def admin_email_assignment_status():
    """Return all email accounts with their assignment status."""
    assignment_map = {}
    for client in client_accounts_col.find(
        {}, {"_id": 1, "username": 1, "display_name": 1, "assigned_emails": 1}
    ):
        for item in normalize_assigned_emails(client.get("assigned_emails", [])):
            em = item["email"]
            if em not in assignment_map:
                assignment_map[em] = {
                    "client_id":       str(client["_id"]),
                    "client_username": client["username"],
                    "client_display":  client.get("display_name") or client["username"],
                }
    accounts = list(
        email_accounts_col.find({}, {"pop3_password": 0}).sort("added_at", DESCENDING)
    )
    result = []
    for a in accounts:
        em = a["email"]
        acct_type = a.get("account_type", "pop3")
        result.append({
            "_id":          str(a["_id"]),
            "email":        em,
            "account_type": acct_type,
            "pop3_host":    a.get("pop3_host", DEFAULT_HOST) if acct_type == "pop3" else "gmail-forwarded",
            "pop3_port":    a.get("pop3_port", DEFAULT_PORT) if acct_type == "pop3" else 0,
            "added_at":     dt_iso(a.get("added_at")) if a.get("added_at") else "",
            "assigned_to":  assignment_map.get(em),
        })
    unassigned = sum(1 for r in result if r["assigned_to"] is None)
    return jsonify({
        "accounts":         result,
        "total":            len(result),
        "unassigned_count": unassigned,
        "assigned_count":   len(result) - unassigned,
    })


@app.route("/admin/api/email-accounts", methods=["POST"])
@admin_required
def admin_add_email():
    data = request.json or {}
    em   = (data.get("email") or "").strip().lower()
    pw   = (data.get("password") or "").strip()
    host = (data.get("host") or DEFAULT_HOST).strip() or DEFAULT_HOST
    port = int(data.get("port") or DEFAULT_PORT)

    if not em:
        return jsonify({"error": "email required"}), 400

    # Outlook / Microsoft addresses → Gmail-forwarded account (no POP3 test)
    if is_outlook_email(em):
        account_type = "gmail_forwarded"
        doc = {
            "email":        em,
            "account_type": account_type,
            "added_at":     datetime.now(timezone.utc),
            "added_by":     session.get("admin_username", "admin"),
        }
    else:
        if not pw:
            return jsonify({"error": "password required for POP3 accounts"}), 400
        # Verify POP3 connectivity before saving
        try:
            conn = connect_pop3(host, port, em, pw)
            conn.quit()
        except Exception as e:
            return jsonify({"error": f"فشل الاتصال بالخادم: {str(e)[:120]}"}), 400
        account_type = "pop3"
        doc = {
            "email":        em,
            "account_type": account_type,
            "pop3_password": pw,
            "pop3_host":    host,
            "pop3_port":    port,
            "added_at":     datetime.now(timezone.utc),
            "added_by":     session.get("admin_username", "admin"),
        }

    try:
        result = email_accounts_col.insert_one(doc)
        _cache.pop(em, None)
        _cache.pop(f"__gmail__{em}", None)
        return jsonify({"ok": True, "id": str(result.inserted_id), "account_type": account_type})
    except DuplicateKeyError:
        return jsonify({"error": f"البريد '{em}' مضاف مسبقاً"}), 409


@app.route("/admin/api/email-accounts/bulk", methods=["POST"])
@admin_required
def admin_bulk_emails():
    """
    Bulk-add email accounts.
    Format per line: email@example.com:password
    For Outlook domains the password is optional (ignored); write email: or email:anything.
    """
    data = request.json or {}
    raw  = (data.get("text") or "").strip()
    host = (data.get("host") or DEFAULT_HOST).strip() or DEFAULT_HOST
    port = int(data.get("port") or DEFAULT_PORT)
    if not raw:
        return jsonify({"error": "No text provided"}), 400

    added = skipped = errors = 0
    error_list = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # Support both "email:pass" and bare "email" (for Outlook accounts)
        if ":" in line:
            parts = line.split(":", 1)
            em = parts[0].strip().lower()
            pw = parts[1].strip()
        else:
            em = line.lower()
            pw = ""

        if not em or "@" not in em:
            error_list.append(f"بريد غير صالح: {line[:60]}")
            errors += 1
            continue

        if is_outlook_email(em):
            account_type = "gmail_forwarded"
            doc = {
                "email":        em,
                "account_type": account_type,
                "added_at":     datetime.now(timezone.utc),
                "added_by":     session.get("admin_username", "admin"),
            }
        else:
            if not pw:
                error_list.append(f"كلمة المرور مطلوبة: {em[:60]}")
                errors += 1
                continue
            account_type = "pop3"
            doc = {
                "email":        em,
                "account_type": account_type,
                "pop3_password": pw,
                "pop3_host":    host,
                "pop3_port":    port,
                "added_at":     datetime.now(timezone.utc),
                "added_by":     session.get("admin_username", "admin"),
            }

        try:
            email_accounts_col.insert_one(doc)
            _cache.pop(em, None)
            _cache.pop(f"__gmail__{em}", None)
            added += 1
        except DuplicateKeyError:
            skipped += 1
        except Exception as exc:
            error_list.append(f"{em}: {exc}")
            errors += 1

    return jsonify({"added": added, "skipped": skipped, "errors": errors, "error_details": error_list[:20]})


@app.route("/admin/api/email-accounts/<acc_id>", methods=["PUT"])
@admin_required
def admin_edit_email(acc_id):
    data   = request.json or {}
    update = {}
    if data.get("password"):
        update["pop3_password"] = data["password"].strip()
    if data.get("host"):
        update["pop3_host"] = data["host"].strip()
    if data.get("port"):
        update["pop3_port"] = int(data["port"])
    if not update:
        return jsonify({"error": "nothing to update"}), 400
    try:
        acc = email_accounts_col.find_one({"_id": ObjectId(acc_id)})
        if not acc:
            return jsonify({"error": "not found"}), 404
        email_accounts_col.update_one({"_id": ObjectId(acc_id)}, {"$set": update})
        _cache.pop(acc["email"], None)
        _cache.pop(f"__gmail__{acc['email']}", None)
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    return jsonify({"ok": True})


@app.route("/admin/api/email-accounts/<acc_id>", methods=["DELETE"])
@admin_required
def admin_delete_email(acc_id):
    try:
        acc = email_accounts_col.find_one({"_id": ObjectId(acc_id)})
        if acc:
            _cache.pop(acc["email"], None)
            _cache.pop(f"__gmail__{acc['email']}", None)
        email_accounts_col.delete_one({"_id": ObjectId(acc_id)})
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    return jsonify({"ok": True})


@app.route("/admin/api/email-accounts/bulk-delete", methods=["DELETE"])
@admin_required
def admin_bulk_delete_emails():
    email_accounts_col.delete_many({})
    _cache.clear()
    return jsonify({"ok": True})


# ── Admin API: Filter Categories ──────────────────────────────────

@app.route("/admin/api/clients/<client_id>/filter-settings", methods=["GET"])
@admin_required
def admin_get_client_filter_settings(client_id):
    try:
        doc = client_accounts_col.find_one(
            {"_id": ObjectId(client_id)}, {"allowed_categories": 1}
        )
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    if not doc:
        return jsonify({"error": "Client not found"}), 404
    return jsonify({"allowed_categories": doc.get("allowed_categories", [])})


@app.route("/admin/api/clients/<client_id>/filter-settings", methods=["PUT"])
@admin_required
def admin_set_client_filter_settings(client_id):
    data = request.json or {}
    raw  = data.get("allowed_categories", [])
    if not isinstance(raw, list):
        return jsonify({"error": "allowed_categories must be a list"}), 400
    valid = []
    for cid in raw:
        try:
            valid.append(str(ObjectId(cid)))
        except Exception:
            pass
    try:
        client_accounts_col.update_one(
            {"_id": ObjectId(client_id)},
            {"$set": {"allowed_categories": valid}}
        )
    except Exception:
        return jsonify({"error": "Invalid client id"}), 400
    return jsonify({"ok": True, "allowed_categories": valid})


@app.route("/admin/api/filter-categories")
@admin_required
def admin_list_categories():
    cats = []
    for c in filter_categories_col.find({}).sort("order", 1):
        cats.append({
            "id":          str(c["_id"]),
            "label":       c["label"],
            "description": c.get("description", ""),
            "patterns":    c.get("patterns", []),
            "enabled":     c.get("enabled", True),
            "order":       c.get("order", 0),
        })
    return jsonify({"categories": cats})


@app.route("/admin/api/filter-categories", methods=["POST"])
@admin_required
def admin_create_category():
    data     = request.json or {}
    label    = (data.get("label") or "").strip()
    desc     = (data.get("description") or "").strip()
    raw_pats = (data.get("patterns") or "")
    if not label:
        return jsonify({"error": "label required"}), 400
    if isinstance(raw_pats, list):
        raw_list = [p.strip() for p in raw_pats if p.strip()]
    else:
        raw_list = [p.strip() for p in raw_pats.splitlines() if p.strip()]
    patterns = [normalize_text(p) for p in raw_list if normalize_text(p)]
    count = filter_categories_col.count_documents({})
    result = filter_categories_col.insert_one({
        "label":       label,
        "description": desc,
        "patterns":    patterns,
        "enabled":     True,
        "order":       count,
        "created_at":  datetime.now(timezone.utc),
    })
    return jsonify({"ok": True, "id": str(result.inserted_id)})


@app.route("/admin/api/filter-categories/<cat_id>", methods=["PUT"])
@admin_required
def admin_edit_category(cat_id):
    data   = request.json or {}
    update = {}
    if "label" in data and data["label"].strip():
        update["label"] = data["label"].strip()
    if "description" in data:
        update["description"] = data["description"].strip()
    if "patterns" in data:
        raw = data["patterns"]
        if isinstance(raw, list):
            raw_list = [p.strip() for p in raw if p.strip()]
        else:
            raw_list = [p.strip() for p in raw.splitlines() if p.strip()]
        update["patterns"] = [normalize_text(p) for p in raw_list if normalize_text(p)]
    if "enabled" in data:
        update["enabled"] = bool(data["enabled"])
    if not update:
        return jsonify({"error": "nothing to update"}), 400
    try:
        filter_categories_col.update_one({"_id": ObjectId(cat_id)}, {"$set": update})
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    return jsonify({"ok": True})


@app.route("/admin/api/filter-categories/<cat_id>", methods=["DELETE"])
@admin_required
def admin_delete_category(cat_id):
    try:
        filter_categories_col.delete_one({"_id": ObjectId(cat_id)})
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    return jsonify({"ok": True})


# ── Admin API: Activity ───────────────────────────────────────────

@app.route("/admin/api/activity")
@admin_required
def admin_all_activity():
    logs = list(login_activity_col.find({}, {"_id": 0}).sort("timestamp", DESCENDING).limit(200))
    for l in logs:
        if l.get("timestamp"):
            l["timestamp"] = dt_iso(l["timestamp"])
    return jsonify({"activity": logs})


@app.route("/admin/api/activity", methods=["DELETE"])
@admin_required
def admin_clear_activity():
    result = login_activity_col.delete_many({})
    return jsonify({"ok": True, "deleted_count": result.deleted_count})


# ── Admin API: Gmail / OAuth Configuration ────────────────────────

@app.route("/admin/api/gmail-config")
@admin_required
def admin_gmail_config():
    """Return Gmail OAuth configuration status (no secrets exposed)."""
    creds_cfg   = get_stored_credentials_config()
    token_info  = get_stored_token_info()
    has_creds   = bool(creds_cfg)
    has_token   = bool(token_info)
    token_valid = False
    gmail_lib   = GMAIL_AVAILABLE

    if has_token and GMAIL_AVAILABLE:
        try:
            creds = Credentials.from_authorized_user_info(token_info, GMAIL_SCOPES)
            if creds and creds.valid:
                token_valid = True
            elif creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(GoogleRequest())
                    save_stored_token_info(json.loads(creds.to_json()))
                    token_valid = True
                except Exception:
                    token_valid = False
        except Exception:
            token_valid = False

    creds_preview = None
    if has_creds:
        try:
            section = creds_cfg.get("installed") or creds_cfg.get("web") or {}
            creds_preview = {
                "client_id":  section.get("client_id", ""),
                "project_id": section.get("project_id", ""),
            }
        except Exception:
            pass

    return jsonify({
        "gmail_lib_installed": gmail_lib,
        "has_credentials":     has_creds,
        "has_token":           has_token,
        "token_valid":         token_valid,
        "credentials_preview": creds_preview,
        "storage":             "mongodb",
    })


@app.route("/admin/api/gmail-config", methods=["PUT"])
@admin_required
def admin_update_gmail_credentials():
    """Save Google client credentials into MongoDB."""
    data    = request.json or {}
    content = (data.get("credentials_json") or "").strip()
    if not content:
        return jsonify({"error": "credentials_json required"}), 400
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"JSON غير صالح: {e}"}), 400
    if "installed" not in parsed and "web" not in parsed:
        return jsonify({"error": "ملف غير صالح: يجب أن يحتوي على مفتاح 'installed' أو 'web'"}), 400
    try:
        save_stored_credentials_config(parsed)
        return jsonify({"ok": True, "message": "تم حفظ الاعتمادات في MongoDB. يجب إعادة التوثيق."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/gmail-auth-url")
@admin_required
def admin_gmail_auth_url():
    """Generate a Google OAuth2 authorization URL (PKCE verifier is persisted in MongoDB)."""
    if not GMAIL_AVAILABLE:
        return jsonify({"error": "مكتبة google-auth غير مثبّتة. شغّل: pip install google-auth google-auth-oauthlib google-api-python-client"}), 500
    if not get_stored_credentials_config():
        return jsonify({"error": "لم يتم حفظ اعتمادات Google بعد — الصق credentials.json واحفظه أولاً"}), 400
    try:
        redirect_uri = _gmail_redirect_uri()
        flow = _build_gmail_flow(redirect_uri)
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        # PKCE: must reuse the same code_verifier when exchanging the auth code
        if not flow.code_verifier:
            return jsonify({"error": "فشل إنشاء code_verifier — حدّث google-auth-oauthlib"}), 500
        _save_oauth_pending(flow.code_verifier, state, redirect_uri)
        return jsonify({
            "auth_url": auth_url,
            "redirect_uri": redirect_uri,
            "auto": True,
            "message": "افتح الرابط، وافق على الصلاحيات — سيتم التوثيق تلقائياً بعد العودة.",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/gmail-oauth-callback")
def admin_gmail_oauth_redirect():
    """Google redirects here after consent. Exchange code using saved PKCE verifier."""
    err = request.args.get("error")
    if err:
        _clear_oauth_pending()
        return (
            "<!doctype html><html lang='ar' dir='rtl'><meta charset='utf-8'>"
            f"<title>فشل التوثيق</title><body style='font-family:sans-serif;background:#0f1117;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0'>"
            f"<div style='text-align:center;max-width:420px;padding:2rem'><h2 style='color:#f25f7a'>فشل التوثيق</h2>"
            f"<p>{err}</p><p><a href='/admin' style='color:#4f8ef7'>العودة للوحة التحكم</a></p></div></body></html>"
        ), 400

    code = (request.args.get("code") or "").strip()
    state = (request.args.get("state") or "").strip()
    if not code:
        return (
            "<!doctype html><html lang='ar' dir='rtl'><meta charset='utf-8'>"
            "<title>خطأ</title><body style='font-family:sans-serif;background:#0f1117;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0'>"
            "<div style='text-align:center'><h2>لم يُستلم كود التوثيق</h2>"
            "<p><a href='/admin' style='color:#4f8ef7'>العودة</a></p></div></body></html>"
        ), 400

    if not GMAIL_AVAILABLE or not get_stored_credentials_config():
        return "Gmail OAuth not available", 500

    pending = _load_oauth_pending()
    if not pending or not pending.get("code_verifier"):
        return (
            "<!doctype html><html lang='ar' dir='rtl'><meta charset='utf-8'>"
            "<title>انتهت الجلسة</title><body style='font-family:sans-serif;background:#0f1117;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0'>"
            "<div style='text-align:center;max-width:420px;padding:2rem'><h2 style='color:#f25f7a'>انتهت جلسة التوثيق</h2>"
            "<p>أعد إنشاء رابط التوثيق من لوحة التحكم ثم حاول مرة أخرى.</p>"
            "<p><a href='/admin' style='color:#4f8ef7'>العودة للوحة التحكم</a></p></div></body></html>"
        ), 400

    if pending.get("state") and state and pending["state"] != state:
        _clear_oauth_pending()
        return "Invalid OAuth state", 400

    try:
        flow = _build_gmail_flow(pending["redirect_uri"])
        flow.code_verifier = pending["code_verifier"]
        flow.fetch_token(code=code)
        save_stored_token_info(json.loads(flow.credentials.to_json()))
        _cache.clear()
        return (
            "<!doctype html><html lang='ar' dir='rtl'><meta charset='utf-8'>"
            "<title>تم التوثيق</title>"
            "<meta http-equiv='refresh' content='2;url=/admin?gmail_oauth=ok'>"
            "<body style='font-family:sans-serif;background:#0f1117;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0'>"
            "<div style='text-align:center;max-width:420px;padding:2rem'>"
            "<div style='width:64px;height:64px;border-radius:50%;background:rgba(34,197,94,.15);display:flex;align-items:center;justify-content:center;margin:0 auto 1.2rem;font-size:2rem'>✓</div>"
            "<h2 style='color:#22c55e;margin:0 0 .5rem'>تم التوثيق بنجاح</h2>"
            "<p style='color:#9aa3b5'>تم حفظ التوكن في MongoDB. جاري العودة…</p>"
            "<p><a href='/admin?gmail_oauth=ok' style='color:#4f8ef7'>اضغط هنا إذا لم يتم التحويل</a></p>"
            "</div></body></html>"
        )
    except Exception as e:
        return (
            "<!doctype html><html lang='ar' dir='rtl'><meta charset='utf-8'>"
            "<title>فشل التوثيق</title><body style='font-family:sans-serif;background:#0f1117;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0'>"
            f"<div style='text-align:center;max-width:480px;padding:2rem'><h2 style='color:#f25f7a'>فشل التوثيق</h2>"
            f"<p style='word-break:break-word'>{str(e)[:300]}</p>"
            "<p><a href='/admin' style='color:#4f8ef7'>العودة وإعادة المحاولة</a></p></div></body></html>"
        ), 400


@app.route("/admin/api/gmail-auth-callback", methods=["POST"])
@admin_required
def admin_gmail_auth_callback():
    """Manual fallback: exchange a pasted authorization code (uses saved PKCE verifier)."""
    if not GMAIL_AVAILABLE:
        return jsonify({"error": "مكتبة google-auth غير مثبّتة"}), 500
    data = request.json or {}
    code = (data.get("code") or "").strip()
    if not code:
        return jsonify({"error": "auth code required"}), 400
    if not get_stored_credentials_config():
        return jsonify({"error": "لم يتم حفظ اعتمادات Google بعد"}), 400

    pending = _load_oauth_pending()
    if not pending or not pending.get("code_verifier"):
        return jsonify({
            "error": "لا توجد جلسة توثيق نشطة. اضغط «ربط حساب Google» أولاً، ثم الصق الكود من نفس الجلسة."
        }), 400

    try:
        flow = _build_gmail_flow(pending["redirect_uri"])
        flow.code_verifier = pending["code_verifier"]
        flow.fetch_token(code=code)
        save_stored_token_info(json.loads(flow.credentials.to_json()))
        _cache.clear()
        return jsonify({"ok": True, "message": "تم التوثيق بنجاح ✓ (محفوظ في MongoDB)"})
    except Exception as e:
        return jsonify({"error": f"فشل التوثيق: {str(e)[:200]}"}), 400


@app.route("/admin/api/gmail-token", methods=["DELETE"])
@admin_required
def admin_delete_gmail_token():
    """Delete the stored OAuth token to force re-authentication."""
    clear_stored_token()
    _cache.clear()
    return jsonify({"ok": True, "message": "تم حذف التوكن من MongoDB. يجب إعادة التوثيق."})


# ─── Entry Point ──────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
