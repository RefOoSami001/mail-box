import os

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS = os.path.join(BASE_DIR, "cred.json")
TOKEN = os.path.join(BASE_DIR, "token.json")


def authenticate():
    creds = None
    if os.path.exists(TOKEN):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN, SCOPES)
        except (ValueError, KeyError):
            creds = None

    if creds and creds.expired and creds.refresh_token:
        try:
            print("[*] Access token expired. Refreshing...")
            creds.refresh(Request())
            print("[+] Token refreshed successfully!")
        except RefreshError as error:
            print(f"[!] Refresh failed: {error}")
            creds = None

    if not creds or not creds.valid:
        print("[*] Starting Google OAuth authentication...")
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS, SCOPES)
        creds = flow.run_local_server(
            host="localhost",
            port=0,
            open_browser=True,
            access_type="offline",
            prompt="consent",
        )
        print("[+] Authentication successful!")

    with open(TOKEN, "w", encoding="utf-8") as file:
        file.write(creds.to_json())
    print("[+] Saved token.json")
    return build("gmail", "v1", credentials=creds)


if __name__ == "__main__":
    service = authenticate()
    response = service.users().messages().list(userId="me", labelIds=["INBOX"], maxResults=1).execute()
    print("[+] Hub inbox reachable. Restart the app so the new token is saved to MongoDB.")
    print("[+] Then redeploy if the production host should use this token.")
