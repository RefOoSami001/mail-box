import poplib
import email as email_lib
import os
import re
import unicodedata
import calendar
import functools
import secrets
import time
import json
import base64
import urllib.parse
import requests
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from pymongo import MongoClient, DESCENDING
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime, timedelta, timezone

# ─── App ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
# Trust X-Forwarded-* from Koyeb / reverse proxies
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
if os.environ.get("FORCE_HTTPS", "1") == "1" and os.environ.get("PUBLIC_BASE_URL", "").startswith("https"):
    app.config["SESSION_COOKIE_SECURE"] = True

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
message_bodies_col    = db["message_bodies"]
oauth_states_col      = db["oauth_states"]

client_accounts_col.create_index("username", unique=True)
email_accounts_col.create_index("email", unique=True)
login_activity_col.create_index([("client_id", 1), ("timestamp", DESCENDING)])
login_activity_col.create_index([("timestamp", DESCENDING)])
# Shared body cache across gunicorn workers (auto-expire)
try:
    message_bodies_col.create_index("cached_at", expireAfterSeconds=int(os.environ.get("MSG_BODY_TTL_SECONDS", 7200)))
    message_bodies_col.create_index([("email", 1), ("uid", 1)], unique=True)
    oauth_states_col.create_index("created_at", expireAfterSeconds=900)
except Exception:
    pass

_cache: dict = {}
_oauth_pending_mem: dict = {}
FETCH_LIMIT = 250

# Outlook Mobile public client — same as LOGIN_TO_TOKEN / READ_EMAILS / RENEW_TOKEN
MS_CLIENT_ID = os.environ.get("MS_CLIENT_ID", "9e5f94bc-e8a4-4e73-b8be-63364c29d753")
MS_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MS_AUTH_URL  = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
MS_DEVICE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
MS_GRAPH_ME  = "https://graph.microsoft.com/v1.0/me"
MS_GRAPH_INBOX = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
MS_GRAPH_MSG = "https://graph.microsoft.com/v1.0/me/messages"
MS_SCOPE     = "openid profile email offline_access User.Read https://graph.microsoft.com/Mail.Read"

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


def is_hotmail_account(acc):
    if not acc:
        return False
    return acc.get("account_type") == "hotmail" or bool(acc.get("refresh_token"))


def _request_host_port():
    host = (request.headers.get("X-Forwarded-Host") or request.host or "").split(",")[0].strip()
    hostname = (host.split(":")[0] or "").lower()
    if ":" in host and host.split(":")[-1].isdigit():
        port = host.split(":")[-1]
    else:
        port = str(os.environ.get("PORT", 5000))
    return hostname, port


def _is_loopback_request():
    hostname, _ = _request_host_port()
    return hostname in ("127.0.0.1", "localhost")


def hotmail_redirect_uri():
    """
    Microsoft callback with no extra path (handled on GET /).
    Local: http://localhost:<port>
    Deployed: https://host  (same popup login as local)
    """
    override = (os.environ.get("MS_REDIRECT_URI") or "").strip()
    if override:
        return override.rstrip("/")
    hostname, port = _request_host_port()
    if hostname in ("127.0.0.1", "localhost"):
        return f"http://localhost:{port}"
    proto = (request.headers.get("X-Forwarded-Proto") or request.scheme or "https").split(",")[0].strip().lower()
    if proto != "http":
        proto = "https"
    host = (request.headers.get("X-Forwarded-Host") or request.host or hostname).split(",")[0].strip()
    if ":" in host and host.rsplit(":", 1)[-1].isdigit():
        host_name, host_port = host.rsplit(":", 1)
        if (proto == "https" and host_port == "443") or (proto == "http" and host_port == "80"):
            host = host_name
    return f"{proto}://{host}"


def _save_oauth_state(state, doc):
    doc = dict(doc)
    doc["_id"] = state
    doc["created_at"] = doc.get("created_at") or datetime.now(timezone.utc)
    _oauth_pending_mem[state] = doc
    try:
        oauth_states_col.replace_one({"_id": state}, doc, upsert=True)
    except Exception as exc:
        print(f"[HOTMAIL] oauth state mongo save failed: {exc}")


def _load_oauth_state(state):
    doc = _oauth_pending_mem.get(state)
    if doc:
        return doc
    try:
        return oauth_states_col.find_one({"_id": state})
    except Exception as exc:
        print(f"[HOTMAIL] oauth state mongo load failed: {exc}")
        return None


def _delete_oauth_state(state):
    _oauth_pending_mem.pop(state, None)
    try:
        oauth_states_col.delete_one({"_id": state})
    except Exception:
        pass


def _normalize_msa_email(val):
    if val is None:
        return ""
    if isinstance(val, (list, tuple)):
        for item in val:
            got = _normalize_msa_email(item)
            if got:
                return got
        return ""
    text = str(val).lower().strip()
    if "#" in text and "@" in text:
        text = text.split("#")[-1].strip()
    if text.startswith("live.com#"):
        text = text[9:]
    return text if "@" in text and " " not in text else ""


def _email_from_jwt(token):
    try:
        parts = (token or "").split(".")
        if len(parts) != 3:
            return ""
        pad = "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        for key in ("preferred_username", "email", "upn", "unique_name", "verified_primary_email"):
            got = _normalize_msa_email(payload.get(key))
            if got:
                return got
        got = _normalize_msa_email(payload.get("emails"))
        if got:
            return got
    except Exception:
        pass
    return ""


def _msa_email_from_token(access_token, id_token=None):
    for token in (id_token, access_token):
        got = _email_from_jwt(token)
        if got:
            return got
    try:
        me = _graph_request(
            "GET",
            MS_GRAPH_ME,
            access_token,
            params={"$select": "mail,userPrincipalName,proxyAddresses,otherMails"},
        )
        print(f"[HOTMAIL] /me HTTP {me.status_code} {me.text[:180]}")
        if me.status_code == 200:
            u = me.json()
            for key in ("mail", "userPrincipalName"):
                got = _normalize_msa_email(u.get(key))
                if got:
                    return got
            got = _normalize_msa_email(u.get("otherMails"))
            if got:
                return got
            for proxy in u.get("proxyAddresses") or []:
                got = _normalize_msa_email(str(proxy).split(":", 1)[-1])
                if got:
                    return got
    except Exception as exc:
        print(f"[HOTMAIL] /me failed: {exc}")
    try:
        res = _graph_request(
            "GET",
            MS_GRAPH_INBOX,
            access_token,
            params={"$top": 8, "$select": "toRecipients,ccRecipients"},
        )
        if res.status_code == 200:
            counts = {}
            for m in res.json().get("value") or []:
                for field in ("toRecipients", "ccRecipients"):
                    for rec in m.get(field) or []:
                        got = _normalize_msa_email((rec.get("emailAddress") or {}).get("address"))
                        if got:
                            counts[got] = counts.get(got, 0) + 1
            if counts:
                preferred = [e for e in counts if e.endswith((".outlook.com", ".hotmail.com", ".live.com", ".msn.com"))]
                pool = preferred or list(counts)
                return max(pool, key=lambda e: counts[e])
    except Exception as exc:
        print(f"[HOTMAIL] inbox identity lookup failed: {exc}")
    return ""


def _exchange_ms_auth_code(code, redirect_uri):
    """Single token request — an auth code can be redeemed only once."""
    payload = {
        "client_id": MS_CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "scope": MS_SCOPE,
    }
    data = _ms_token_request(payload)
    if data.get("access_token"):
        print(f"[HOTMAIL] token exchange ok redirect_uri={redirect_uri}")
        return data
    err = data.get("error_description") or data.get("error") or data
    print(f"[HOTMAIL] token exchange failed uri={redirect_uri} err={str(err)[:300]}")
    return data


def _ms_token_request(payload):
    res = requests.post(
        MS_TOKEN_URL,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )
    try:
        data = res.json()
    except Exception:
        data = {"error": "invalid_response", "error_description": (res.text or "")[:200]}
    if not data.get("access_token"):
        print(f"[HOTMAIL] token HTTP {res.status_code}: {str(data)[:300]}")
    return data


def graph_refresh_access(acc):
    """
    Exchange stored refresh_token for an access_token.
    Persist rotated refresh_token (90-day rolling window).
    """
    refresh_token = (acc or {}).get("refresh_token") or ""
    if not refresh_token:
        raise RuntimeError("لا يوجد توكن Hotmail لهذا البريد. أعد ربط الحساب من لوحة الإدارة.")
    client_id = acc.get("ms_client_id") or MS_CLIENT_ID
    last = {}
    for scope in (MS_SCOPE, "https://graph.microsoft.com/mail.read offline_access"):
        data = _ms_token_request({
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scope,
        })
        last = data
        if data.get("access_token"):
            _persist_hotmail_tokens(acc, data, client_id)
            return data["access_token"]
    err = last.get("error_description") or last.get("error") or "token refresh failed"
    raise RuntimeError(f"فشل تجديد توكن Hotmail: {str(err).split(chr(10))[0][:160]}")


def _persist_hotmail_tokens(acc, data, client_id=None):
    access_token = data.get("access_token") or ""
    new_refresh = data.get("refresh_token") or acc.get("refresh_token") or ""
    now = datetime.now(timezone.utc)
    expires_in = int(data.get("expires_in") or 3600)
    fields = {
        "refresh_token": new_refresh,
        "access_token": access_token,
        "token_updated_at": now,
        "access_expires_at": now + timedelta(seconds=max(expires_in - 60, 60)),
        "account_type": "hotmail",
        "ms_client_id": client_id or acc.get("ms_client_id") or MS_CLIENT_ID,
    }
    acc["refresh_token"] = new_refresh
    acc["access_token"] = access_token
    query = {"_id": acc["_id"]} if acc.get("_id") else {"email": (acc.get("email") or "").lower()}
    if not (query.get("_id") or query.get("email")):
        return
    try:
        email_accounts_col.update_one(query, {"$set": fields})
    except Exception as exc:
        print(f"[HOTMAIL] failed to persist tokens: {exc}")


def graph_stored_access(acc):
    token = (acc or {}).get("access_token") or ""
    if not token:
        raise RuntimeError("لا يوجد توكن وصول محفوظ. اطلب من المشرف تجديد توكن Hotmail.")
    return token


def _graph_request(method, url, access_token, **kwargs):
    headers = kwargs.pop("headers", {})
    headers["Authorization"] = f"Bearer {access_token}"
    headers.setdefault("Accept", "application/json")
    res = None
    for attempt in range(2):
        res = requests.request(method, url, headers=headers, timeout=12, **kwargs)
        if res.status_code == 429:
            wait = min(int(res.headers.get("Retry-After", 1)), 4)
            time.sleep(wait)
            continue
        return res
    return res


def _graph_message_to_summary(m):
    sender = (m.get("from") or {}).get("emailAddress") or {}
    sender_addr = sender.get("address") or ""
    sender_name = sender.get("name") or sender_addr
    subject = normalize_text(m.get("subject") or "") or "(بدون موضوع)"
    received = m.get("receivedDateTime") or ""
    msg_ts = None
    date_disp = received or "—"
    try:
        msg_dt = datetime.fromisoformat(received.replace("Z", "+00:00"))
        if msg_dt.tzinfo is None:
            msg_dt = msg_dt.replace(tzinfo=timezone.utc)
        msg_ts = msg_dt.isoformat()
        date_disp = msg_dt.strftime("%d %b %Y  %H:%M")
    except Exception:
        msg_ts = received or None
    body_obj = m.get("body") or {}
    content = body_obj.get("content") or ""
    ctype = (body_obj.get("contentType") or "html").lower()
    body_type = "html" if ctype == "html" else "plain"
    preview = (m.get("bodyPreview") or "").strip()
    if not preview and content:
        preview = BeautifulSoup(content, "html.parser").get_text()[:300].strip()
    uid = m.get("id") or ""
    summary = {
        "uid":         uid,
        "subject":     subject,
        "sender_name": sender_name,
        "sender_addr": sender_addr,
        "date":        date_disp,
        "timestamp":   msg_ts,
        "preview":     preview[:300],
    }
    body_entry = {"body": content or "(لا يوجد محتوى)", "body_type": body_type}
    return summary, body_entry


def _graph_list_messages(access_token, limit):
    select = "id,subject,from,receivedDateTime,bodyPreview,isRead"
    top = min(max(limit, 1), 25)
    attempts = [
        (MS_GRAPH_INBOX, {"$top": top, "$orderby": "receivedDateTime desc", "$select": select}),
        (MS_GRAPH_INBOX, {"$top": top, "$select": select}),
    ]
    last_error = "unknown"
    for url, params in attempts:
        res = _graph_request("GET", url, access_token, params=params)
        if res.status_code == 200:
            return res.json().get("value") or []
        if res.status_code in (401, 403):
            raise RuntimeError("انتهت صلاحية توكن Hotmail. اطلب من المشرف تجديد التوكن.")
        last_error = f"HTTP {res.status_code} {res.text[:120]}"
    raise RuntimeError(f"فشل جلب بريد Hotmail: {last_error}")


def fetch_hotmail_messages(email_addr, acc, limit=15):
    access_token = graph_stored_access(acc)
    raw_msgs = _graph_list_messages(access_token, limit)
    new_summaries = []
    for m in raw_msgs:
        uid = m.get("id") or ""
        if not uid:
            continue
        summary, _body = _graph_message_to_summary(m)
        new_summaries.append(summary)
        if len(new_summaries) >= limit:
            break
    entry = _cache.setdefault(email_addr, {"summaries": [], "bodies": {}})
    entry["summaries"] = new_summaries
    return new_summaries


def fetch_hotmail_message_body(email_addr, uid, acc):
    access_token = graph_stored_access(acc)
    encoded = urllib.parse.quote(uid, safe="")
    res = _graph_request(
        "GET",
        f"{MS_GRAPH_MSG}/{encoded}",
        access_token,
        params={"$select": "id,subject,from,receivedDateTime,bodyPreview,body,isRead"},
    )
    if res.status_code in (401, 403):
        raise RuntimeError("انتهت صلاحية توكن Hotmail. اطلب من المشرف تجديد التوكن.")
    if res.status_code != 200:
        raise RuntimeError(f"تعذّر جلب الرسالة من Hotmail: HTTP {res.status_code}")
    summary, body_entry = _graph_message_to_summary(res.json())
    _cache_put_body(email_addr, uid, summary, body_entry, email_addr)
    return body_entry


def upsert_hotmail_account(email_addr, refresh_token, client_id, added_by="admin", access_token="", expires_in=3600):
    email_addr = (email_addr or "").strip().lower()
    now = datetime.now(timezone.utc)
    existing = email_accounts_col.find_one({"email": email_addr})
    fields = {
        "email": email_addr,
        "account_type": "hotmail",
        "refresh_token": refresh_token,
        "ms_client_id": client_id or MS_CLIENT_ID,
        "token_updated_at": now,
    }
    if access_token:
        fields["access_token"] = access_token
        fields["access_expires_at"] = now + timedelta(seconds=max(int(expires_in or 3600) - 60, 60))
    if existing:
        email_accounts_col.update_one({"_id": existing["_id"]}, {"$set": fields})
        _cache.pop(email_addr, None)
        return str(existing["_id"]), False
    fields["added_at"] = now
    fields["added_by"] = added_by
    result = email_accounts_col.insert_one(fields)
    return str(result.inserted_id), True


# ─── POP3 Fetch ───────────────────────────────────────────────────

def fetch_email_messages(email_addr, pop3_password, pop3_host, pop3_port, limit=FETCH_LIMIT):
    existing   = _cache.get(email_addr, {"summaries": [], "bodies": {}})
    known_uids = {m["uid"] for m in existing["summaries"]}
    known_bodies = existing.get("bodies", {})

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
            # Skip only when we already have BOTH summary and body
            if uid in known_uids and uid in known_bodies:
                continue

            raw_lines = conn.retr(int(num))[1]
            raw       = b"\n".join(raw_lines)
            msg       = email_lib.message_from_bytes(raw)

            summary, body_entry = _build_summary(msg, uid)
            new_summaries.append(summary)
            new_bodies[uid] = body_entry
            _cache_put_body(email_addr, uid, summary, body_entry, email_addr)

        except Exception:
            continue

    conn.quit()

    merged_summaries = new_summaries + [m for m in existing["summaries"] if m["uid"] not in new_bodies]
    merged_bodies    = {**existing["bodies"], **new_bodies}
    _cache[email_addr] = {"summaries": merged_summaries, "bodies": merged_bodies}
    return merged_summaries


def _cache_put_body(cache_key: str, uid: str, summary: dict, body_entry: dict, email_addr: str = ""):
    """Store a single message body in process cache + MongoDB (shared across workers)."""
    entry = _cache.setdefault(cache_key, {"summaries": [], "bodies": {}})
    entry["bodies"][uid] = body_entry
    if not any(m.get("uid") == uid for m in entry["summaries"]):
        entry["summaries"].insert(0, summary)
    email_key = (email_addr or cache_key).lower()
    if email_key and uid:
        try:
            message_bodies_col.update_one(
                {"email": email_key, "uid": uid},
                {
                    "$set": {
                        "email": email_key,
                        "uid": uid,
                        "body": body_entry.get("body", ""),
                        "body_type": body_entry.get("body_type", "plain"),
                        "summary": summary,
                        "cached_at": datetime.now(timezone.utc),
                    }
                },
                upsert=True,
            )
        except Exception as exc:
            print(f"[CACHE] mongo body save failed: {exc}")


def _get_cached_body(uid: str, email_addr: str = ""):
    """Look up body in process RAM, then MongoDB."""
    for cached in _cache.values():
        bodies = cached.get("bodies", {})
        if uid in bodies:
            return bodies[uid]
    query = {"uid": uid}
    if email_addr:
        query["email"] = email_addr.lower()
    try:
        doc = message_bodies_col.find_one(query, sort=[("cached_at", DESCENDING)])
        if doc:
            body_entry = {"body": doc.get("body", ""), "body_type": doc.get("body_type", "plain")}
            # hydrate local cache for this worker
            email_key = doc.get("email") or email_addr
            cache_key = email_key
            if cache_key:
                entry = _cache.setdefault(cache_key, {"summaries": [], "bodies": {}})
                entry["bodies"][uid] = body_entry
            return body_entry
    except Exception as exc:
        print(f"[CACHE] mongo body load failed: {exc}")
    return None


def fetch_single_message_body(email_addr: str, uid: str, acc: dict) -> dict:
    """
    Load one message body from Hotmail Graph or POP3 when it is missing
    from this worker's in-memory cache.
    """
    cache_key = email_addr
    uid = (uid or "").strip()

    if is_hotmail_account(acc):
        return fetch_hotmail_message_body(email_addr, uid, acc)

    if not acc.get("pop3_password"):
        raise RuntimeError("لا توجد كلمة مرور POP3 لهذا البريد")

    conn = connect_pop3(
        acc.get("pop3_host", DEFAULT_HOST),
        acc.get("pop3_port", DEFAULT_PORT),
        email_addr,
        acc["pop3_password"],
    )
    try:
        try:
            _, uidl_list, _ = conn.uidl()
        except Exception:
            _, list_raw, _ = conn.list()
            uidl_list = [
                f"{item.decode().split()[0]} uid{item.decode().split()[0]}".encode()
                for item in list_raw
            ]
        msg_num = None
        for item in uidl_list:
            parts = item.decode(errors="ignore").split(" ", 1)
            if len(parts) < 2:
                continue
            num_s, server_uid = parts[0].strip(), parts[1].strip()
            if server_uid == uid or server_uid.lower() == uid.lower():
                msg_num = int(num_s)
                break
            # fallback ids like "uid12" from servers without UIDL
            if uid == f"uid{num_s}" or uid == num_s:
                msg_num = int(num_s)
                break
        if msg_num is None:
            raise RuntimeError("الرسالة غير موجودة على الخادم")
        raw_lines = conn.retr(msg_num)[1]
        raw = b"\n".join(raw_lines)
        msg = email_lib.message_from_bytes(raw)
        summary, body_entry = _build_summary(msg, uid)
        _cache_put_body(cache_key, uid, summary, body_entry, email_addr)
        return body_entry
    finally:
        try:
            conn.quit()
        except Exception:
            pass




# ─── Client Routes ────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    # Outlook redirects to http://localhost:<port>/?code=... (no extra path allowed)
    raw_qs = (request.query_string or b"").decode("ascii", errors="ignore")
    if request.method == "GET" and ("code=" in raw_qs or "error=" in raw_qs):
        return complete_hotmail_oauth_from_request()
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

    def sort_newest(msg_list):
        def key(m):
            return m.get("timestamp") or ""
        return sorted(msg_list, key=key, reverse=True)

    cutoff_minutes = int(os.environ.get("EMAIL_CUTOFF_MINUTES", 20))
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=cutoff_minutes)

    cache_key = email_addr
    warning   = None

    try:
        if is_hotmail_account(acc):
            summaries = fetch_hotmail_messages(email_addr, acc)
        else:
            if not acc.get("pop3_password"):
                return jsonify({"error": "لا توجد كلمة مرور POP3 لهذا البريد"}), 400
            summaries = fetch_email_messages(
                email_addr,
                acc["pop3_password"],
                acc.get("pop3_host", DEFAULT_HOST),
                acc.get("pop3_port", DEFAULT_PORT),
            )
    except Exception as e:
        err = str(e)
        if "توكن" in err:
            return jsonify({"error": err[:180]}), 401
        cached = _cache.get(cache_key, {}).get("summaries", [])
        if not cached:
            return jsonify({"error": f"فشل جلب الرسائل: {err[:180]}"}), 503
        summaries = cached
        warning   = "تعذّر تحديث الرسائل — يتم عرض نسخة محفوظة مؤقتاً"

    if normalized_patterns:
        summaries = apply_filter_patterns(summaries, normalized_patterns)
    summaries = sort_newest(summaries)
    summaries = apply_time_cutoff(summaries, cutoff)
    if summaries:
        summaries = [summaries[0]]

    # Embed body in the response so opening never depends on another worker's RAM
    out_messages = []
    for m in summaries:
        item = dict(m)
        uid = m.get("uid")
        body_entry = None
        if uid:
            body_entry = (
                _cache.get(cache_key, {}).get("bodies", {}).get(uid)
                or _get_cached_body(uid, email_addr)
            )
            if not body_entry and is_hotmail_account(acc):
                try:
                    body_entry = fetch_hotmail_message_body(email_addr, uid, acc)
                except Exception as exc:
                    print(f"[HOTMAIL] body fetch skipped: {exc}")
        if body_entry:
            item["body"] = body_entry.get("body", "")
            item["body_type"] = body_entry.get("body_type", "plain")
        out_messages.append(item)

    log_activity(session["client_id"], session["client_username"],
                 f"fetch:{email_addr}:cat:{category_label}", get_client_ip())

    session["last_fetch_email"] = email_addr

    return jsonify({
        "messages":  out_messages,
        "total":     len(out_messages),
        "warning":   warning,
        "category":  category_label,
        "cached":    warning is not None and "نسخة محفوظة" in (warning or ""),
    })


@app.route("/api/message/<path:uid>")
@client_required
def api_message(uid):
    """
    Return message body. Prefer RAM → MongoDB → live Hotmail/POP3 fetch.
    """
    uid = (uid or "").strip()

    email_addr = (
        (request.args.get("email") or "").strip().lower()
        or (session.get("last_fetch_email") or "").strip().lower()
    )

    # 1) Shared cache (this worker RAM or MongoDB)
    cached_body = _get_cached_body(uid, email_addr)
    if cached_body:
        return jsonify(cached_body)

    # 2) Resolve mailbox so we can fetch on demand
    if not email_addr:
        return jsonify({
            "error": "الرسالة غير محمّلة. أعد جلب الرسائل ثم افتحها مرة أخرى."
        }), 404

    acc = email_accounts_col.find_one({"email": email_addr})
    if not acc:
        return jsonify({"error": "هذا البريد غير مسجّل في النظام"}), 404

    try:
        body_entry = fetch_single_message_body(email_addr, uid, acc)
        return jsonify(body_entry)
    except Exception as e:
        return jsonify({
            "error": f"تعذّر تحميل الرسالة: {str(e)[:160]}"
        }), 404


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
    accounts = list(email_accounts_col.find({}, {"pop3_password": 0, "refresh_token": 0, "access_token": 0}).sort("added_at", DESCENDING))
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
        email_accounts_col.find({}, {"pop3_password": 0, "refresh_token": 0, "access_token": 0}).sort("added_at", DESCENDING)
    )
    result = []
    for a in accounts:
        em = a["email"]
        acct_type = a.get("account_type", "pop3")
        result.append({
            "_id":          str(a["_id"]),
            "email":        em,
            "account_type": acct_type,
            "pop3_host":    a.get("pop3_host", DEFAULT_HOST) if acct_type != "hotmail" else "hotmail",
            "pop3_port":    a.get("pop3_port", DEFAULT_PORT) if acct_type != "hotmail" else 0,
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
    if not pw:
        return jsonify({"error": "password required for POP3 accounts"}), 400
    try:
        conn = connect_pop3(host, port, em, pw)
        conn.quit()
    except Exception as e:
        return jsonify({"error": f"فشل الاتصال بالخادم: {str(e)[:120]}"}), 400
    account_type = "pop3"
    doc = {
        "email":         em,
        "account_type":  account_type,
        "pop3_password": pw,
        "pop3_host":     host,
        "pop3_port":     port,
        "added_at":      datetime.now(timezone.utc),
        "added_by":      session.get("admin_username", "admin"),
    }

    try:
        result = email_accounts_col.insert_one(doc)
        _cache.pop(em, None)
        return jsonify({"ok": True, "id": str(result.inserted_id), "account_type": account_type})
    except DuplicateKeyError:
        return jsonify({"error": f"البريد '{em}' مضاف مسبقاً"}), 409


@app.route("/admin/api/email-accounts/bulk", methods=["POST"])
@admin_required
def admin_bulk_emails():
    """
    Bulk-add email accounts.
    POP3: email@example.com:password
    Hotmail token (from LOGIN_TO_TOKEN accounts.txt): email|password|refresh_token|client_id
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
        if "|" in line and line.count("|") >= 2:
            parts = [p.strip() for p in line.split("|")]
            em = parts[0].lower()
            refresh_token = parts[2] if len(parts) > 2 else ""
            client_id = parts[3] if len(parts) > 3 else MS_CLIENT_ID
            if not em or "@" not in em or not refresh_token:
                error_list.append(f"سطر Hotmail غير صالح: {line[:60]}")
                errors += 1
                continue
            try:
                upsert_hotmail_account(em, refresh_token, client_id, session.get("admin_username", "admin"))
                _cache.pop(em, None)
                added += 1
            except DuplicateKeyError:
                skipped += 1
            except Exception as exc:
                error_list.append(f"{em}: {exc}")
                errors += 1
            continue
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

        if not pw:
            error_list.append(f"كلمة المرور مطلوبة: {em[:60]}")
            errors += 1
            continue
        account_type = "pop3"
        doc = {
            "email":         em,
            "account_type":  account_type,
            "pop3_password": pw,
            "pop3_host":     host,
            "pop3_port":     port,
            "added_at":      datetime.now(timezone.utc),
            "added_by":      session.get("admin_username", "admin"),
        }

        try:
            email_accounts_col.insert_one(doc)
            _cache.pop(em, None)
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


def _hotmail_oauth_result_html(ok, title, message, email=""):
    color = "#22c55e" if ok else "#f25f7a"
    icon = "✓" if ok else "!"
    email_js = email.replace("\\", "\\\\").replace("'", "\\'")
    return f"""<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8">
<title>{title}</title>
<body style="font-family:sans-serif;background:#0f1117;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
<div style="text-align:center;max-width:440px;padding:2rem">
  <div style="width:64px;height:64px;border-radius:50%;background:rgba(34,197,94,.15);display:flex;align-items:center;justify-content:center;margin:0 auto 1.2rem;font-size:2rem;color:{color}">{icon}</div>
  <h2 style="color:{color};margin:0 0 .5rem">{title}</h2>
  <p style="color:#9aa3b5;line-height:1.7">{message}</p>
  <p><a href="/admin" style="color:#4f8ef7">العودة للوحة التحكم</a></p>
</div>
<script>
try {{
  if (window.opener) {{
    window.opener.postMessage({{type:'hotmail_oauth', ok:{str(ok).lower()}, email:'{email_js}'}}, '*');
    setTimeout(function(){{ window.close(); }}, 800);
  }}
}} catch (e) {{}}
</script>
</body></html>"""


def _raw_query_arg(name):
    """Read a query param without turning '+' into space (Microsoft auth codes)."""
    qs = (request.query_string or b"").decode("utf-8", errors="replace")
    for part in qs.split("&"):
        if not part or "=" not in part:
            continue
        key, val = part.split("=", 1)
        if urllib.parse.unquote(key) == name:
            return urllib.parse.unquote(val)
    return (request.args.get(name) or "").strip()


def _hotmail_account_from_tokens(access_token, refresh_token, admin_user="admin", id_token=None, expires_in=3600):
    user_email = _msa_email_from_token(access_token, id_token=id_token)
    if not user_email or "@" not in user_email:
        return None, "تعذر قراءة عنوان البريد من Microsoft. أعد الربط ووافق على الصلاحيات."
    acc_id, created = upsert_hotmail_account(
        user_email,
        refresh_token,
        MS_CLIENT_ID,
        admin_user,
        access_token=access_token,
        expires_in=expires_in,
    )
    return {"email": user_email, "id": acc_id, "created": created}, None


def complete_hotmail_oauth_from_request():
    err = _raw_query_arg("error")
    if err:
        desc = _raw_query_arg("error_description") or err
        return _hotmail_oauth_result_html(False, "فشل التوثيق", desc[:300]), 400

    code = _raw_query_arg("code")
    state = _raw_query_arg("state")
    if not code or not state:
        return _hotmail_oauth_result_html(False, "خطأ", "لم يُستلم كود التوثيق."), 400

    pending = _load_oauth_state(state)
    if not pending:
        return _hotmail_oauth_result_html(
            False, "انتهت الجلسة", "أعد الضغط على «ربط حساب Hotmail» ثم حاول مرة أخرى."
        ), 400

    redirect_uri = pending.get("redirect_uri") or hotmail_redirect_uri()
    admin_user = pending.get("admin_username", "admin")

    data = _exchange_ms_auth_code(code, redirect_uri)
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token") or ""
    if not access_token:
        err_msg = data.get("error_description") or data.get("error") or str(data)[:200]
        print(f"[HOTMAIL] exchange failed: {err_msg}")
        return _hotmail_oauth_result_html(False, "فشل التوثيق", str(err_msg)[:400]), 400
    if not refresh_token:
        refresh_token = access_token
        print("[HOTMAIL] no refresh_token in response; storing access token as fallback")

    _delete_oauth_state(state)
    info, err_msg = _hotmail_account_from_tokens(
        access_token,
        refresh_token,
        admin_user,
        id_token=data.get("id_token"),
        expires_in=data.get("expires_in") or 3600,
    )
    if err_msg:
        return _hotmail_oauth_result_html(False, "فشل التوثيق", err_msg), 400
    verb = "تمت إضافة" if info["created"] else "تم تحديث توكن"
    return _hotmail_oauth_result_html(
        True,
        "تم التوثيق بنجاح",
        f"{verb} الحساب <b>{info['email']}</b>. يمكنك إغلاق هذه النافذة.",
        email=info["email"],
    )


@app.route("/admin/api/hotmail-auth-url")
@admin_required
def admin_hotmail_auth_url():
    admin_user = session.get("admin_username", "admin")
    redirect_uri = hotmail_redirect_uri()
    state = secrets.token_urlsafe(24)
    _save_oauth_state(state, {
        "kind": "auth_code",
        "admin_username": admin_user,
        "redirect_uri": redirect_uri,
    })
    params = {
        "client_id": MS_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": MS_SCOPE,
        "prompt": "login",
        "state": state,
    }
    auth_url = MS_AUTH_URL + "?" + urllib.parse.urlencode(params)
    return jsonify({
        "ok": True,
        "mode": "loopback",
        "auth_url": auth_url,
        "redirect_uri": redirect_uri,
    })


@app.route("/admin/api/hotmail-device-poll")
@admin_required
def admin_hotmail_device_poll():
    poll_id = (request.args.get("poll_id") or "").strip()
    pending = _load_oauth_state(poll_id) if poll_id else None
    if not pending or pending.get("kind") != "device":
        return jsonify({"error": "انتهت جلسة التوثيق"}), 400
    data = _ms_token_request({
        "client_id": MS_CLIENT_ID,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": pending.get("device_code") or "",
    })
    err = data.get("error")
    if err in ("authorization_pending", "slow_down"):
        return jsonify({"ok": False, "pending": True, "error": err})
    if err:
        return jsonify({"ok": False, "pending": False, "error": data.get("error_description") or err}), 400
    refresh_token = data.get("refresh_token") or ""
    access_token = data.get("access_token")
    if not access_token:
        return jsonify({"ok": False, "error": "لم يُرجع Microsoft توكن"}), 400
    if not refresh_token:
        refresh_token = access_token
    _delete_oauth_state(poll_id)
    info, err_msg = _hotmail_account_from_tokens(
        access_token,
        refresh_token,
        pending.get("admin_username", "admin"),
        id_token=data.get("id_token"),
        expires_in=data.get("expires_in") or 3600,
    )
    if err_msg:
        return jsonify({"ok": False, "error": err_msg}), 400
    return jsonify({"ok": True, "email": info["email"], "created": info["created"]})


@app.route("/admin/api/hotmail-oauth-callback")
def admin_hotmail_oauth_callback():
    return complete_hotmail_oauth_from_request()


@app.route("/admin/api/hotmail-renew/<acc_id>", methods=["POST"])
@admin_required
def admin_hotmail_renew_one(acc_id):
    try:
        acc = email_accounts_col.find_one({"_id": ObjectId(acc_id)})
    except Exception:
        acc = None
    if not acc:
        return jsonify({"error": "الحساب غير موجود"}), 404
    if not is_hotmail_account(acc):
        return jsonify({"error": "هذا ليس حساب Hotmail"}), 400
    try:
        graph_refresh_access(acc)
    except Exception as exc:
        return jsonify({"error": str(exc)[:200]}), 400
    return jsonify({"ok": True, "email": acc.get("email")})


@app.route("/admin/api/hotmail-renew-all", methods=["POST"])
@admin_required
def admin_hotmail_renew_all():
    accounts = list(email_accounts_col.find({
        "$or": [{"account_type": "hotmail"}, {"refresh_token": {"$exists": True, "$ne": ""}}],
    }))
    ok = fail = 0
    errors = []
    for acc in accounts:
        try:
            graph_refresh_access(acc)
            ok += 1
        except Exception as exc:
            fail += 1
            errors.append(f"{acc.get('email')}: {exc}")
    return jsonify({
        "ok": True,
        "renewed": ok,
        "failed": fail,
        "total": len(accounts),
        "error_details": errors[:20],
    })


# ─── Entry Point ──────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
