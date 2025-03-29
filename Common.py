import re
import base64
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator


def extract_header_components(header):
    message_info = []
    
    date = ''
    spf = ''
    dkim = ''
    dmarc = ''
    returning_path = ''
    from_field = ''
    subject_field = ''
    to_field = ''
    message_id = ''
    received = ''
    
    for i in header:
        if i.get('name') == "Authentication-Results":
            index = header.index(i)
            temp = header[index]
            dmarc = re.findall(r'dmarc=pass|dmarc=fail', temp.get('value'))
        elif dmarc == '' or dmarc == 'none':
            dmarc = 'none'
            # print(authentication_results)
            
        if i.get('name') == "Received-SPF":
            index = header.index(i)
            spf = header[index].get('value')
        elif spf == '' or spf == 'none':
            spf = 'none'
            
        if i.get('name') == "DKIM-Signature":
            index = header.index(i)
            dkim = header[index].get('value')
            # print(message_id)
        elif dkim == '' or dkim == 'none':
            dkim = 'none'
            
        if i.get('name') == "Return-Path":
            index = header.index(i)
            returning_path = header[index].get('value')
            # print(returning_path)
        elif returning_path == '' or returning_path == 'none':
            returning_path = 'none'
            
        if i.get('name') == "From":
            index = header.index(i)
            from_field = header[index].get('value')
            # print(from_field)
        elif from_field == '' or from_field == 'none':
            from_field = 'none'
        
        if i.get('name') == "Subject":
            index = header.index(i)
            subject_field = header[index].get('value')
            # print(subject_field)
        elif subject_field == '' or subject_field == 'none':
            subject_field = 'none'
        
        if i.get('name') == "To":
            index = header.index(i)
            to_field = header[index].get('value')
            # print(to_field)
        elif to_field == '' or to_field == 'none':
            to_field = 'none'
        
        if i.get('name') == "Message-ID":
            index = header.index(i)
            message_id = header[index].get('value')
            # print(message_id)
        elif message_id == '' or message_id == 'none':
            message_id = 'none'
        
        if i.get('name') == "Received":
            index = header.index(i)
            received = header[index].get('value')
            # print(message_id)
        elif received == '' or received == 'none':
            received = 'none'
        
        if i.get('name') == "Date":
            index = header.index(i)
            date = header[index].get('value')
            # print(message_id)
        elif date == '' or date == 'none':
            date = 'none'
            
    new_item = {
        "message_id" : message_id,
        "date": date,
        "subject" : subject_field,
        "from" : from_field,
        "to" : to_field,
        "dmarc" : dmarc,
        "spf" : spf,
        "dkim" : dkim,
        "return_path" : returning_path,
        "received" : received
    }
        
    message_info.append(new_item)
    return message_info

# For instance, if you send a test email to 30 mailboxes and it lands in the inbox of 20 recipients, the calculation would be 20/30*10, resulting in a Spam Score of 6.6 out of 10.

        

    
def gmail_pharser(message_id, service):
    
        # Step 2: Get the full message using the ID
        message_response = service.users().messages().get(
            userId='me',
            id=message_id,
            format='full'
        ).execute()

        # Step 3: Parse the message content
        payload = message_response['payload']
        header = payload.get('headers', [])
        parts = payload.get('parts', [])
        
        return header      
        
        

def import_eml_message(eml_path, service):
    """Import an EML file into Gmail using the same style as messages().get()"""

    with open(eml_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    original_message_id = msg['Message-ID']
    
    # Rebuild raw message
    buffer = io.BytesIO()
    BytesGenerator(buffer, policy=policy.default).flatten(msg)
    raw = base64.urlsafe_b64encode(buffer.getvalue()).decode()

    # Import with custom metadata
    message_response = service.users().messages().import_(
        userId='me',
        body={
            'raw': raw,
            'labelIds': ['INBOX'],
            'internalDateSource': 'dateHeader',  # Preserve original timestamp
            'payload': {
                'headers': [{
                    'name': 'X-Original-Message-ID',
                    'value': original_message_id
                }]
            }
        }
    ).execute()

    # Add original ID to response
    message_response['originalMessageId'] = original_message_id
    message_response['gmailMessageId'] = message_response['id']

    print(f"Original ID: {original_message_id}")
    print(f"Gmail ID: {message_response['id']}")
    return message_response

    
    