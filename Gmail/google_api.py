import os.path
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',  # Read-only access
    'https://www.googleapis.com/auth/gmail.modify',    # Read/write access
    'https://www.googleapis.com/auth/gmail.compose'    # Full access
]

CREDENTIALS_FILE = 'credentials.json' 
TOKEN_FILE = 'token.json'

def init_gmail_service():
    """Shows basic usage of the Gmail API.
    Initializes and returns the Gmail API service object.
    """
    creds = None

    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Make sure you have your credentials.json file from Google Cloud Console
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('gmail', 'v1', credentials=creds)
        print("Succesfully connected with google")
        return service
    except HttpError as error:
        print(f'An error occurred building the service: {error}')
        return None