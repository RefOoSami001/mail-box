# Flask POP3 MailBox — MongoDB Edition

## What's new

- **MongoDB** replaces SQLite for storing user credentials
- **Admin Panel** at `/admin` (password-protected)
  - Add / edit / delete user accounts
  - Bulk import users from plain `email:password` text
  - Global subject filters — only show emails whose subject matches
- Subject filtering applies to all users globally (not per-user)

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Environment variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `dev-secret-key` | Flask session secret — **change in production** |
| `ADMIN_PASSWORD` | `admin123` | Password for `/admin` — **change in production** |
| `MONGO_URI` | bundled URI | MongoDB connection string |
| `FLASK_DEBUG` | `0` | Set to `1` for debug mode |
| `PORT` | `5000` | Server port |

```bash
export SECRET_KEY="your-strong-secret"
export ADMIN_PASSWORD="your-admin-password"
```

### 3. Run locally

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.  
Admin panel: `http://127.0.0.1:5000/admin`

## Admin Panel

Navigate to `/admin/login` and enter your `ADMIN_PASSWORD`.

### Users tab
- Add individual users (email + POP3 password)
- Edit or delete existing users
- Search through the user list

### Bulk Import tab
- Paste any number of lines in `email:password` format
- Choose **Skip duplicates** or **Overwrite duplicates**
- Results show added / skipped / error counts

### Subject Filters tab
- Add keyword patterns (e.g. `Netflix: Your sign-in code`)
- Toggle filters on/off without deleting them
- When **no filter is active**, all emails are shown
- When one or more filters are active, only emails whose subject **contains** at least one pattern are shown (case-insensitive)

## Deploy (Render / Heroku-style)

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`
- Set env vars: `SECRET_KEY`, `ADMIN_PASSWORD`, `MONGO_URI` (if different)

## Architecture

```
app.py                 Flask app (POP3 + admin routes)
templates/
  login.html           User login page
  inbox.html           Email inbox UI
  admin_login.html     Admin authentication
  admin.html           Admin panel (users + bulk + filters)
requirements.txt       Python dependencies
Procfile               Gunicorn start command
```
