# Flask POP3 Inbox App

## What this project needs

- Python 3.11 or newer
- Flask
- BeautifulSoup4

## Setup locally

1. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
2. Set a secret key for production:
   ```powershell
   $env:SECRET_KEY = "your-secret-key"
   ```
3. Run locally:
   ```powershell
   python app.py
   ```
4. Open `http://127.0.0.1:5000` in your browser.

## Deploy to a cloud host

### Render / Heroku-style hosts

- Push your repository to GitHub.
- Create a new Web service.
- Set the build command to:
  ```bash
  pip install -r requirements.txt
  ```
- Set the start command to:
  ```bash
  gunicorn app:app
  ```
- Set environment variables:
  - `SECRET_KEY` = a strong secret string
  - `FLASK_DEBUG` = `0`

### PythonAnywhere

- Upload your files.
- Configure the web app to use the WSGI entrypoint `app:app`.
- Set `SECRET_KEY` in the web app environment variables.

## Important notes

- This app stores POP3 credentials in Flask session data. That is not secure for public deployment.
- For a public deployment, use a server-side session store and avoid storing raw passwords in cookies.
- Ensure the POP3 server host, port, username, and password are correct for your email provider.
