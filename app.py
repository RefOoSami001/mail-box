import poplib
import email as email_lib
import os
import json
import calendar
import functools
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from pymongo import MongoClient, DESCENDING
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone

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
email_bodies_col      = db["email_bodies"]

client_accounts_col.create_index("username", unique=True)
email_accounts_col.create_index("email", unique=True)
login_activity_col.create_index([("client_id", 1), ("timestamp", DESCENDING)])
login_activity_col.create_index([("timestamp", DESCENDING)])
email_bodies_col.create_index("uid", unique=True)

_cache: dict = {}
FETCH_LIMIT = 60

# ─── i18n ────────────────────────────────────────────────────────

SUPPORTED_LANGS = ["ar", "en", "fr"]
DEFAULT_LANG = "ar"
_translations: dict = {}

def _load_translations():
    locales_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales")
    for lang in SUPPORTED_LANGS:
        path = os.path.join(locales_dir, f"{lang}.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                _translations[lang] = json.load(f)
        except Exception:
            _translations[lang] = {}

_load_translations()


def get_lang():
    return session.get("lang", DEFAULT_LANG)


def tr(key, lang=None, **kwargs):
    """Translate a key server-side (for use in route handlers)."""
    if lang is None:
        lang = get_lang()
    trans = _translations.get(lang, _translations.get(DEFAULT_LANG, {}))
    val = trans.get(key, _translations.get(DEFAULT_LANG, {}).get(key, key))
    for k, v in kwargs.items():
        val = val.replace("{" + k + "}", str(v))
    return val


@app.route("/set-language/<lang>")
def set_language(lang):
    if lang in SUPPORTED_LANGS:
        session["lang"] = lang
    next_url = request.referrer or url_for("login")
    return redirect(next_url)


@app.context_processor
def inject_i18n():
    lang = get_lang()
    trans = _translations.get(lang, _translations.get(DEFAULT_LANG, {}))

    def t(key, **kwargs):
        val = trans.get(key, _translations.get(DEFAULT_LANG, {}).get(key, key))
        for k, v in kwargs.items():
            val = val.replace("{" + k + "}", str(v))
        return val

    return dict(
        t=t,
        lang=lang,
        dir_attr="rtl" if lang == "ar" else "ltr",
        translations_json=json.dumps(trans, ensure_ascii=False),
        supported_langs=SUPPORTED_LANGS,
    )

# ─── Helpers ─────────────────────────────────────────────────────

def dt_iso(dt):
    if not dt:
        return "—"
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def add_one_month(date_str):
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
    result = []
    for item in (raw_list or []):
        if isinstance(item, str):
            result.append({"email": item, "start_date": None, "end_date": None, "assigned_at": None})
        elif isinstance(item, dict) and item.get("email"):
            result.append(item)
    return result


def is_email_active(item):
    today = datetime.now(timezone.utc).date().isoformat()
    start = item.get("start_date")
    end   = item.get("end_date")
    if start and today < start:
        return False
    if end and today > end:
        return False
    return True


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


def connect_pop3(host, port, user, password):
    conn = poplib.POP3_SSL(host, int(port))
    conn.user(user)
    conn.pass_(password)
    return conn


def decode_str(value):
    if value is None:
        return ""
    parts = decode_header(value)
    result = []
    for chunk, enc in parts:
        if isinstance(chunk, bytes):
            result.append(chunk.decode(enc or "utf-8", errors="ignore"))
        else:
            result.append(chunk)
    return "".join(result)


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
    return plain or tr("no_content"), "plain"


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
        if len(new_summaries) + len(existing["summaries"]) >= limit:
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

            subject     = decode_str(msg.get("Subject", "")) or tr("no_content")
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

            new_summaries.append({
                "uid":         uid,
                "subject":     subject,
                "sender_name": sender_name or sender_addr,
                "sender_addr": sender_addr,
                "date":        format_date(msg.get("Date", "")),
                "timestamp":   msg_ts,
                "preview":     preview,
            })
            new_bodies[uid] = {"body": body, "body_type": body_type}

        except Exception:
            continue

    conn.quit()

    # Persist bodies to MongoDB so all Gunicorn workers can read them
    for uid, body_doc in new_bodies.items():
        try:
            email_bodies_col.update_one(
                {"uid": uid},
                {"$set": {"uid": uid, "email_addr": email_addr,
                           "body": body_doc["body"], "body_type": body_doc["body_type"],
                           "fetched_at": datetime.now(timezone.utc)}},
                upsert=True,
            )
        except Exception:
            pass

    merged_summaries = new_summaries + existing["summaries"]
    merged_bodies    = {**existing["bodies"], **new_bodies}
    _cache[email_addr] = {"summaries": merged_summaries, "bodies": merged_bodies}
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
            error = tr("err_enter_credentials")
        else:
            doc = client_accounts_col.find_one({"username": username})
            if not doc:
                error = tr("err_user_not_found")
                log_activity(None, username, "login_failed_no_user", get_client_ip(), False)
            elif doc.get("status") == "suspended":
                error = tr("err_account_suspended")
                log_activity(str(doc["_id"]), username, "login_blocked_suspended", get_client_ip(), False)
            elif not check_password_hash(doc["password_hash"], password):
                error = tr("err_wrong_password")
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
    # Only remove client keys — preserves admin session in same browser
    session.pop("client_id", None)
    session.pop("client_username", None)
    session.pop("client_display", None)
    return redirect(url_for("login"))


# ─── Client API ───────────────────────────────────────────────────

@app.route("/api/categories")
@client_required
def api_categories():
    cats = [
        {"id": str(c["_id"]), "label": c["label"], "description": c.get("description", "")}
        for c in filter_categories_col.find({"enabled": True}).sort("order", 1)
    ]
    return jsonify({"categories": cats})


@app.route("/api/my-emails")
@client_required
def api_my_emails():
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
        return jsonify({"error": tr("dash_invalid_email")}), 400

    acc = email_accounts_col.find_one({"email": email_addr})
    if not acc:
        return jsonify({"error": tr("err_user_not_found")}), 404

    patterns = []
    category_label = tr("stat_active") if False else "الكل"
    if category_id:
        try:
            cat = filter_categories_col.find_one({"_id": ObjectId(category_id)})
            if cat:
                patterns       = cat.get("patterns", [])
                category_label = cat["label"]
        except Exception:
            pass

    try:
        summaries = fetch_email_messages(
            email_addr,
            acc["pop3_password"],
            acc.get("pop3_host", DEFAULT_HOST),
            acc.get("pop3_port", DEFAULT_PORT),
        )
    except Exception as e:
        cached = _cache.get(email_addr, {}).get("summaries", [])
        if not cached:
            return jsonify({"error": f"{tr('error_generic')}: {str(e)[:120]}"}), 503
        summaries = cached
        warning = tr("dash_cached_warning")
        if patterns:
            summaries = [m for m in summaries if any(p.lower() in m["subject"].lower() for p in patterns)]
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=20)
        summaries = [m for m in summaries if m.get("timestamp") and datetime.fromisoformat(m["timestamp"]) >= cutoff]
        if summaries:
            summaries = [summaries[0]]
        return jsonify({"messages": summaries, "total": len(summaries), "warning": warning, "category": category_label, "cached": True})

    if patterns:
        summaries = [m for m in summaries if any(p.lower() in m["subject"].lower() for p in patterns)]
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=20)
    summaries = [m for m in summaries if m.get("timestamp") and datetime.fromisoformat(m["timestamp"]) >= cutoff]
    if summaries:
        summaries = [summaries[0]]

    log_activity(session["client_id"], session["client_username"],
                 f"fetch:{email_addr}:cat:{category_label}", get_client_ip())

    return jsonify({
        "messages":  summaries,
        "total":     len(summaries),
        "warning":   None,
        "category":  category_label,
        "cached":    False,
    })


@app.route("/api/message/<uid>")
@client_required
def api_message(uid):
    # 1. Try in-memory cache first (fast path)
    for email_addr, cached in _cache.items():
        bodies = cached.get("bodies", {})
        if uid in bodies:
            return jsonify(bodies[uid])
    # 2. Fall back to MongoDB (works across all Gunicorn workers)
    doc = email_bodies_col.find_one({"uid": uid}, {"_id": 0, "body": 1, "body_type": 1})
    if doc:
        return jsonify({"body": doc["body"], "body_type": doc["body_type"]})
    return jsonify({"error": tr("dash_msg_not_in_cache")}), 404


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
        error = tr("err_admin_wrong_credentials")
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
            "email_count":     len(assigned),
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
        return jsonify({"error": f"Username '{username}' already taken"}), 409


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
        return jsonify({"error": "Username already taken"}), 409
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
            error_list.append(f"Bad format: {line[:50]}")
            errors += 1
            continue
        parts    = line.split(":", 1)
        username = parts[0].strip().lower()
        password = parts[1].strip()
        if not username or not password:
            error_list.append(f"Empty field: {line[:50]}")
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
        return jsonify({"error": f"Email '{email}' not found in email accounts"}), 404
    try:
        doc = client_accounts_col.find_one({"_id": ObjectId(client_id)})
    except Exception:
        return jsonify({"error": "Invalid client id"}), 400
    if not doc:
        return jsonify({"error": "Client not found"}), 404
    assigned = normalize_assigned_emails(doc.get("assigned_emails", []))
    if any(item["email"] == email for item in assigned):
        return jsonify({"error": f"Email '{email}' already assigned to this client"}), 409
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
        new_start = end
        new_end   = add_one_month(end)
        item["start_date"] = new_start
        item["end_date"]   = new_end
        updated += 1
    client_accounts_col.update_one(
        {"_id": ObjectId(client_id)},
        {"$set": {"assigned_emails": assigned}}
    )
    return jsonify({"ok": True, "updated": updated})


# ── Admin API: Email Accounts ──────────────────────────────────────

@app.route("/admin/api/email-accounts")
@admin_required
def admin_list_emails():
    accounts = list(email_accounts_col.find({}, {"pop3_password": 0}).sort("added_at", DESCENDING))
    for a in accounts:
        a["_id"]      = str(a["_id"])
        a["added_at"] = dt_iso(a.get("added_at")) if a.get("added_at") else ""
    return jsonify({"accounts": accounts})


@app.route("/admin/api/email-accounts", methods=["POST"])
@admin_required
def admin_add_email():
    data  = request.json or {}
    em    = (data.get("email") or "").strip().lower()
    pw    = (data.get("password") or "").strip()
    host  = (data.get("host") or DEFAULT_HOST).strip() or DEFAULT_HOST
    port  = int(data.get("port") or DEFAULT_PORT)
    if not em or not pw:
        return jsonify({"error": "email and password required"}), 400
    try:
        conn = connect_pop3(host, port, em, pw)
        conn.quit()
    except Exception as e:
        return jsonify({"error": f"Connection failed: {str(e)[:120]}"}), 400
    try:
        result = email_accounts_col.insert_one({
            "email":         em,
            "pop3_password": pw,
            "pop3_host":     host,
            "pop3_port":     port,
            "added_at":      datetime.now(timezone.utc),
            "added_by":      session.get("admin_username", "admin"),
        })
        _cache.pop(em, None)
        return jsonify({"ok": True, "id": str(result.inserted_id)})
    except DuplicateKeyError:
        return jsonify({"error": f"Email '{em}' already added"}), 409


@app.route("/admin/api/email-accounts/bulk", methods=["POST"])
@admin_required
def admin_bulk_emails():
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
        if ":" not in line:
            error_list.append(f"Bad format: {line[:60]}")
            errors += 1
            continue
        parts = line.split(":", 1)
        em = parts[0].strip().lower()
        pw = parts[1].strip()
        if not em or not pw:
            error_list.append(f"Empty field: {line[:60]}")
            errors += 1
            continue
        if "@" not in em:
            error_list.append(f"Invalid email: {em[:60]}")
            errors += 1
            continue
        try:
            email_accounts_col.insert_one({
                "email":         em,
                "pop3_password": pw,
                "pop3_host":     host,
                "pop3_port":     port,
                "added_at":      datetime.now(timezone.utc),
                "added_by":      session.get("admin_username", "admin"),
            })
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
    result = email_accounts_col.delete_many({})
    _cache.clear()
    return jsonify({"ok": True, "deleted_count": result.deleted_count})


# ── Admin API: Filter Categories ──────────────────────────────────

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
    patterns = [p.strip() for p in raw_pats.splitlines() if p.strip()]
    count    = filter_categories_col.count_documents({})
    filter_categories_col.insert_one({
        "label":       label,
        "description": desc,
        "patterns":    patterns,
        "enabled":     True,
        "order":       count,
        "created_at":  datetime.now(timezone.utc),
    })
    return jsonify({"ok": True})


@app.route("/admin/api/filter-categories/<cat_id>", methods=["PUT"])
@admin_required
def admin_edit_category(cat_id):
    data     = request.json or {}
    label    = (data.get("label") or "").strip()
    desc     = (data.get("description") or "").strip()
    raw_pats = (data.get("patterns") or "")
    enabled  = data.get("enabled", True)
    if not label:
        return jsonify({"error": "label required"}), 400
    patterns = [p.strip() for p in raw_pats.splitlines() if p.strip()]
    try:
        filter_categories_col.update_one(
            {"_id": ObjectId(cat_id)},
            {"$set": {"label": label, "description": desc, "patterns": patterns, "enabled": bool(enabled)}}
        )
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
def admin_activity():
    logs = list(login_activity_col.find({}, {"_id": 0}).sort("timestamp", DESCENDING).limit(100))
    for l in logs:
        if l.get("timestamp"):
            l["timestamp"] = dt_iso(l["timestamp"])
    return jsonify({"activity": logs})


@app.route("/admin/api/activity", methods=["DELETE"])
@admin_required
def admin_clear_activity():
    result = login_activity_col.delete_many({})
    return jsonify({"ok": True, "deleted_count": result.deleted_count})


if __name__ == "__main__":
    app.run(debug=True)
