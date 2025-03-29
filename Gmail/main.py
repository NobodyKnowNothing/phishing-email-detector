from google_api import init_gmail_service
from Common import gmail_pharser, extract_header_components

if __name__ == '__main__':
    service = init_gmail_service()
    list_response = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    if 'messages' in list_response:
        for message in list_response.get('messages'):
            message_id = message.get('id')
            header = gmail_pharser(message_id,service)
            
            message_info = extract_header_components(header)
            print(message_info)