from google_api import init_gmail_service
    
if __name__ == '__main__':
    service = init_gmail_service()
    list_response = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=1).execute()
    print(list_response)
    if 'messages' in list_response:
        message_id = list_response['messages'][0]['id']
        
        # Step 2: Get the full message using the ID
        message_response = service.users().messages().get(
            userId='me',
            id=message_id,
            format='full'
        ).execute()

        # Step 3: Parse the message content
        payload = message_response['payload']
        headers = payload.get('headers', [])
        parts = payload.get('parts', [])

        # Extract common headers
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
        print("Payload")
        print(payload)
        print("Headers")
        print(headers)
        print("parts")
        print(parts)
        print("Subject")
        print(subject)
        print("sender")
        print(sender)

