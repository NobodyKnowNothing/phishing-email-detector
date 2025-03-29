class Email_Info:
    def __init__(self):
        self.sender
        self.subject
        self.body
        self.dmarc
        self.dkim
        self.spf
        self.date
        self.cc
        pass
    
    
    
def gmail_pharser(message_id, service):
    
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


    
    