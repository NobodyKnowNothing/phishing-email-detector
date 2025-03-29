from google_api import init_gmail_service
from UI import init_UI
from Common import gmail_pharser, extract_header_components, import_eml_message




if __name__ == '__main__':
    
    
    
    init_UI()
    service = init_gmail_service()
    test = import_eml_message("test1.eml",service)
    message_details1 = service.users().messages().get(
    userId='me',
    id=test['id'],
    format='full'
    ).execute()
    print("-----------------------------------------------------------------------------------")

    list_response = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    if 'messages' in list_response:
        for message in list_response.get('messages'):
            message_id = message.get('id')
            header = gmail_pharser(message_id,service)
            
            message_info = extract_header_components(header)
            print(message_info)
            
            
