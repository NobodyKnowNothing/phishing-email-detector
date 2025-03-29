import os.path
import base64
from email.message import EmailMessage
import google.auth
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- Configuration ---
# If modifying these scopes, delete the file token.json.
SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.modify'
]
CREDENTIALS_FILE = 'credentials.json' # Path to your credentials JSON file
TOKEN_FILE = 'token.json'             # Stores the user's access and refresh tokens

# --- Authentication ---
def authenticate_gmail():
    """Shows basic usage of the Gmail API.
    Handles user authentication and returns the API service client.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first time.
    if os.path.exists(TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        except google.auth.exceptions.RefreshError as e:
             print(f"Error loading token: {e}. Might need re-authorization.")
             creds = None # Force re-authentication
        except ValueError as e: # Handle case where token.json might be corrupted
             print(f"Error loading token file (might be invalid format): {e}")
             creds = None


    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print("Credentials expired. Refreshing token...")
            try:
                creds.refresh(Request())
            except google.auth.exceptions.RefreshError as e:
                #TODO :: FIX THIS 
                print(f"Error refreshing token: {e}")
                print("Please re-authorize by deleting token.json and running the script again.")
                # Attempt the full flow if refresh fails
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                # Specify redirect_uri for desktop apps if needed, often managed automatically
                # You might need port=0 for dynamic port assignment
                creds = flow.run_local_server(port=0)
            except Exception as e:
                 print(f"An unexpected error occurred during token refresh: {e}")
                 return None # Cannot proceed without valid credentials
        else:
            print("No valid credentials found. Starting authentication flow...")
            if not os.path.exists(CREDENTIALS_FILE):
                print(f"Error: Credentials file '{CREDENTIALS_FILE}' not found.")
                print("Please download it from Google Cloud Console and place it here.")
                return None
            try:
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                # run_local_server will open a browser tab for user authorization
                creds = flow.run_local_server(port=0)
            except FileNotFoundError:
                 print(f"Error: {CREDENTIALS_FILE} not found.")
                 return None
            except Exception as e:
                 print(f"An error occurred during the authentication flow: {e}")
                 return None

        # Save the credentials for the next run
        try:
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())
            print(f"Credentials saved to {TOKEN_FILE}")
        except Exception as e:
             print(f"Error saving token to {TOKEN_FILE}: {e}")


    # Build the Gmail API service
    try:
        service = build('gmail', 'v1', credentials=creds)
        print("Gmail API service created successfully.")
        return service
    except HttpError as error:
        print(f'An error occurred building the service: {error}')
        return None
    except Exception as e:
        print(f'An unexpected error occurred: {e}')
        return None
