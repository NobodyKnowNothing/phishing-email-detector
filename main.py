from Gmail.google_api import *
from Gmail.UI import *
from Common import *
from Gmail.phishing_check import *


email_infos = []
api_key = ''

def checks(service):
    print("--------------------------------CHECKS--------------------------")
    global email_infos
    for email in email_infos:
        score = 0
        result = 0
        failed_checks = []
        if(email.get('body') != None):
            result = check_key_words(email) 
            score += result
            email["KEY_WORDS_FAIL"] = "Fail"
            
        result = check_dkim(email)
        if(result != 0):
            email["DKIM_FAIL"] = "Fail"
        score += result
        
        result = check_dmarc(email)
        if(result != 0):
            email["DMARC_FAIL"] = "Fail"
        score += result
        result = check_spf(email)
        if(result != 0):
            email["SPF_FAIL"] = "Fail"
        score += result
        urls = fetch_and_extract_urls(service, email["message_id"])
        url_cleaned = []
        for url in urls:
            parts = url.split('/')
            # Get everything after the third slash
            if len(parts) >= 4:
                result = '/'.join(parts[:3])
                if result in url_cleaned:
                    pass
                else:
                    url_cleaned.append(result) 
        print(url_cleaned)
        result = check_urls(url_cleaned,api_key)
        result = result[0]
        if(result != 0):
            email["URLHAUS_FAIL"] = "Fail"

        score += result
        email["threat_status"] = result[1]
        email["threat_type"] = result[2]
        email["fails"] = failed_checks

        result = common_file_names_check(email["payload"])
        if(result != 0):
            email["EXTENSIONS_FAIL"] = "Fail"
        score += result
            
        print("Score: " + str(score))
        email["score"] = score
        #add the label to the email so when in your gmail inbox you will see its been checked
        Low_Threat_id = get_label_id(service, "Low Threat")
        Medium_Threat_id = get_label_id(service, "Medium Threat")
        High_Threat_id = get_label_id(service, "High Threat")

        if  Low_Threat_id and "message_id" in email and email["message_id"] and score <= 15:
            sanitized_id = email["message_id"].strip("<>").replace(" ", "")
            add_label_to_message(service, sanitized_id, [Low_Threat_id])
        elif  Medium_Threat_id and "message_id" in email and email["message_id"] and score > 15 and score < 30:
            sanitized_id = email["message_id"].strip("<>").replace(" ", "")
            add_label_to_message(service, sanitized_id, [Medium_Threat_id])
        elif  High_Threat_id and "message_id" in email and email["message_id"] and score >= 30:
            sanitized_id = email["message_id"].strip("<>").replace(" ", "")
            add_label_to_message(service, sanitized_id, [High_Threat_id])

        add_email(email)       

def import_test_case(path, service):
    global email_infos
    message = import_eml_message(path,service)
    header = gmail_pharser(message.get('id'),service)[0]
    body = gmail_pharser(message.get('id'),service)[1]
    email_infos.append(extract_header_components(header,body,message.get('id'),message))

#phishing emails from our personal accounts that we are using for the test cases
def test_cases(service):
    import_test_case("test_case/test2.eml",service)
    import_test_case("test_case/test3.eml",service)
    import_test_case("test_case/test4.eml",service)


if __name__ == '__main__':
    api_key = open('key.txt', 'r').read()
    
    init_UI()
    
    import_data()
    service = init_gmail_service()
    test_cases(service)    
    list_response = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    if 'messages' in list_response:
        for message in list_response.get('messages'):
            message_id = message.get('id')
            message = gmail_pharser(message_id,service)
            header = message[0]
            body = message[1]
            parts = message[2]
            payload = message[3]
            
            email_infos.append(extract_header_components(header,body, message_id, payload))
    
    checks(service)
    display_UI()

            
            
