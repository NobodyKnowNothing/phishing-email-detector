from google_api import init_gmail_service
from Common import gmail_pharser

if __name__ == '__main__':
    service = init_gmail_service()
    list_response = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=1).execute()
    if 'messages' in list_response:
        message_id = list_response['messages'][0]['id']
        gmail_pharser(message_id,service)
        