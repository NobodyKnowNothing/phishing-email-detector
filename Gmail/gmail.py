import os.path
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def get_gmail_service():
    """Shows basic usage of the Gmail API.
    Initializes and returns the Gmail API service object.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
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
        return service
    except HttpError as error:
        print(f'An error occurred building the service: {error}')
        return None

def get_label_id(service, label_name):
    """Gets the ID of a user label by its name."""
    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        for label in labels:
            if label['name'].lower() == label_name.lower():
                print(f"Found label: Name='{label['name']}', ID='{label['id']}'")
                return label['id']
        print(f"Label '{label_name}' not found.")
        # Optional: Add code here to create the label if not found
        # label_body = {'name': label_name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'}
        # created_label = service.users().labels().create(userId='me', body=label_body).execute()
        # return created_label['id']
        return None
    except HttpError as error:
        print(f'An error occurred getting label ID: {error}')
        return None

def add_label_to_message(service, message_id, label_ids_to_add):
    """Adds specified labels to a message."""
    if not label_ids_to_add:
        print("No label IDs provided to add.")
        return None

    modify_request = {
        'addLabelIds': label_ids_to_add,
        'removeLabelIds': [] # Specify labels to remove here if needed
    }
    try:
        message = service.users().messages().modify(
            userId='me',
            id=message_id,
            body=modify_request
        ).execute()
        print(f"Message ID: {message['id']} modified. Added labels: {label_ids_to_add}")
        # print(f"Labels now on message: {message.get('labelIds')}")
        return message
    except HttpError as error:
        print(f'An error occurred modifying message {message_id}: {error}')
        return None

# --- Main Execution ---
if __name__ == '__main__':
    service = get_gmail_service()

    if service:
        # 1. Find a message ID (replace with your logic to find the correct message)
        # Example: Get the first message in the inbox
        try:
            list_response = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=1).execute()
            messages = list_response.get('messages', [])
            if not messages:
                print("No messages found in Inbox.")
            else:
                message_id_to_label = messages[0]['id']
                print(f"Found message ID: {message_id_to_label}")

                # 2. Define the label name you want to add
                user_label_name = "MyImportantStuff" # Change to your desired label name

                # 3. Get the Label ID for the user label
                label_id_to_add = get_label_id(service, user_label_name)

                # You could also add system labels directly
                system_label_id = "STARRED"

                labels_to_add = []
                if label_id_to_add:
                    labels_to_add.append(label_id_to_add)
                # labels_to_add.append(system_label_id) # Uncomment to add STARRED label too

                # 4. Add the label(s) to the message
                if labels_to_add:
                   add_label_to_message(service, message_id_to_label, labels_to_add)
                else:
                   print(f"Could not find or create label ID for '{user_label_name}', not modifying message.")

        except HttpError as error:
            print(f"An error occurred listing messages: {error}")