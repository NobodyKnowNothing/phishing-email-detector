from Gmail.google_api import *
from Gmail.UI import *
from Common import *
from Gmail.phishing_check import *


email_infos = []

def checks(service):
    print("--------------------------------CHECKS--------------------------")
    global email_infos
    for email in email_infos:
        score = 0
        if(email.get('body') != None):
            score += check_key_words(email) 
            
        score += check_dkim(email)
        score += check_dmarc(email)
        score += check_spf(email)
        
        urls = fetch_and_extract_urls(service, email["message_id"])
        
        score += check_urls(urls)

            
        print("Score: " + str(score))
        email["score"] = score
        #add the label to the email so when in your gmail inbox you will see its been checked
        label_id = get_label_id(service, "Dangerous")
        print(email["message_id"])
        if label_id and "message_id" in email and email["message_id"] and score > 10:
            sanitized_id = email["message_id"].strip("<>").replace(" ", "")
            add_label_to_message(service, sanitized_id, [label_id])
        else:
            print("Skipping email: Invalid ID or missing label.")

        add_email(email)       

def import_test_case(path, service):
    global email_infos
    message = import_eml_message(path,service)
    header = gmail_pharser(message.get('id'),service)[0]
    body = gmail_pharser(message.get('id'),service)[1]
    email_infos.append(extract_header_components(header,body,message.get('id')))

#phishing emails from our personal accounts that we are using for the test cases
def test_cases(service):
    import_test_case("test_case/test2.eml",service)
    import_test_case("test_case/test3.eml",service)
    import_test_case("test_case/test4.eml",service)


if __name__ == '__main__':
    init_UI()
    
    import_data()
    service = init_gmail_service()
    test_cases(service)    
    list_response = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    if 'messages' in list_response:
        for message in list_response.get('messages'):
            message_id = message.get('id')
            header = gmail_pharser(message_id,service)[0]
            body = gmail_pharser(message_id,service)[1]

            email_infos.append(extract_header_components(header,body, message_id))
            
            
    
    checks(service)
    display_UI()

            
            
