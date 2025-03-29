from Gmail.google_api import *
from Gmail.UI import *
from Common import *
from Gmail.phishing_check import *


email_infos = []



def checks():
    print("--------------------------------CHECKS--------------------------")
    global email_infos
    for email in email_infos:
        score = 0
        if(email.get('body') != None):
            score += check_key_words(email)
            
        print("Score: " + str(score))
        add_email(email)
        

        



if __name__ == '__main__':
    init_UI()

    import_data()
    service = init_gmail_service()
    test = import_eml_message("test1.eml",service)
    message_details1 = service.users().messages().get(
    userId='me',
    id=test['id'],
    format='full'
    ).execute()
    
    list_response = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    if 'messages' in list_response:
        for message in list_response.get('messages'):
            message_id = message.get('id')
            header = gmail_pharser(message_id,service)[0]
            body = gmail_pharser(message_id,service)[1]

            email_infos.append(extract_header_components(header,body))
    
    checks()
    display_UI()

            
            
