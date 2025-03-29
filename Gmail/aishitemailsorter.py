import os.path
import base64
import json
import time
import re # Regular expressions for parsing
from email.utils import parseaddr # For parsing 'From' header
from urllib.parse import urlparse # For analyzing URLs

# --- Dependencies ---
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: BeautifulSoup library not found.")
    print("Please install it using: pip install beautifulsoup4")
    exit()

# --- Google API Imports ---
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- Configuration ---
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
CREDENTIALS_FILE = 'credentials.json'
TOKEN_FILE = 'token.json'
PROCESSED_EMAILS_FILE = 'processed_emails.json'

# --- Phishing Detection Configuration ---

# Labels to apply based on indicators (Script will try to create these if they don't exist)
LABEL_AUTH_FAIL = "Phish-Indicator-AuthFail"
LABEL_SUSPICIOUS_LINK = "Phish-Indicator-Link"
LABEL_SUSPICIOUS_ATTACHMENT = "Phish-Indicator-Attachment"
LABEL_SUSPICIOUS_KEYWORD = "Phish-Indicator-Keyword"
LABEL_IMPERSONATION_FLAG = "Phish-Indicator-Impersonation"
LABEL_NEEDS_REVIEW = "Needs-Manual-Review" # Applied if >= MIN_INDICATORS_FOR_REVIEW

# Threshold for applying the main review label
MIN_INDICATORS_FOR_REVIEW = 2 # e.g., if 2 or more indicators are found, apply Needs-Manual-Review

# Keywords/Phrases (lowercase) - Add more as needed
SUSPICIOUS_KEYWORDS = [
    "verify your account", "update your payment", "confirm your identity",
    "password check", "security alert", "account suspended", "urgent action required",
    "invoice attached", "wire transfer request", "gift card purchase", "dear customer",
    "click here to login", "unusual sign-in activity"
]

# Potentially Dangerous Attachment File Extensions/MIME types (lowercase)
BLOCKED_ATTACHMENT_EXTENSIONS = ['.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.js', '.jar', '.ps1', '.dll', '.msi', '.cmd']
BLOCKED_ATTACHMENT_MIMETYPES = ['application/x-msdownload', 'application/octet-stream', 'application/javascript', 'text/javascript'] # Add more risky types

# Basic Link Checks
KNOWN_URL_SHORTENERS = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co'] # Add others if needed
SUSPICIOUS_TLDS = ['.zip', '.mov', '.xyz', '.top', '.info'] # Often abused TLDs

# Impersonation Detection (Basic)
# Define your internal domain(s) and known important names/patterns
# This is highly context-specific and needs careful tuning
INTERNAL_DOMAINS = ['mycompany.com', 'internal.mycompany.com']
IMPORTANT_INTERNAL_NAMES = ['CEO', 'CFO', 'John Doe', 'Jane Smith', 'Finance Department'] # Names or keywords in display names

# --- End Configuration ---

# (get_gmail_service, load_processed_ids, save_processed_ids functions remain largely the same as before)
# ... [Include the previous get_gmail_service, load_processed_ids, save_processed_ids functions here] ...
def get_gmail_service():
    """Initializes and returns the Gmail API service object."""
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                print(f"Error refreshing token: {e}. Need to re-authenticate.")
                creds = None # Force re-authentication
                if os.path.exists(TOKEN_FILE):
                    os.remove(TOKEN_FILE) # Remove invalid token file
        if not creds: # Trigger authentication flow if refresh failed or no token
            if not os.path.exists(CREDENTIALS_FILE):
                print(f"Error: Credentials file '{CREDENTIALS_FILE}' not found.")
                print("Please download it from Google Cloud Console and place it here.")
                return None
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('gmail', 'v1', credentials=creds)
        print("Gmail service created successfully.")
        return service
    except HttpError as error:
        print(f'An error occurred building the service: {error}')
        return None

def load_processed_ids(filename=PROCESSED_EMAILS_FILE):
    """Loads the set of processed email IDs from a JSON file."""
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                return set(data.get('processed_ids', []))
        except json.JSONDecodeError:
            print(f"Warning: Could not decode JSON from {filename}. Starting with empty set.")
            return set()
        except Exception as e:
            print(f"Warning: Error loading {filename}: {e}. Starting with empty set.")
            return set()
    return set()

def save_processed_ids(processed_ids, filename=PROCESSED_EMAILS_FILE):
    """Saves the set of processed email IDs to a JSON file."""
    try:
        with open(filename, 'w') as f:
            json.dump({'processed_ids': sorted(list(processed_ids))}, f, indent=4)
    except Exception as e:
        print(f"Error saving processed IDs to {filename}: {e}")


def get_label_id(service, label_name, label_cache):
    """Gets the ID of a label, using a cache. Creates the label if it doesn't exist."""
    label_name_lower = label_name.lower()
    if label_name_lower in label_cache:
        return label_cache[label_name_lower]

    print(f"Fetching/Verifying ID for label: '{label_name}'")
    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        for label in labels:
            if label['name'].lower() == label_name_lower:
                # print(f"Found existing label: Name='{label['name']}', ID='{label['id']}'")
                label_cache[label_name_lower] = label['id']
                return label['id']

        print(f"Label '{label_name}' not found. Creating it...")
        label_body = {
            'name': label_name,
            'labelListVisibility': 'labelShow',
            'messageListVisibility': 'show'
        }
        created_label = service.users().labels().create(userId='me', body=label_body).execute()
        print(f"Created label: Name='{created_label['name']}', ID='{created_label['id']}'")
        label_cache[label_name_lower] = created_label['id']
        return created_label['id']

    except HttpError as error:
        # Handle label already exists error gracefully if creation races
        if error.resp.status == 409:
             print(f"Label '{label_name}' likely created by another process/run. Refetching...")
             # Clear cache entry if it was somehow wrong and retry fetching
             if label_name_lower in label_cache: del label_cache[label_name_lower]
             time.sleep(1) # Short delay before refetch
             return get_label_id(service, label_name, label_cache) # Try again
        print(f"An error occurred getting or creating label '{label_name}': {error}")
        return None
    except Exception as e:
         print(f"An unexpected error occurred with label '{label_name}': {e}")
         return None


def get_header(headers, name):
    """Gets a specific header value from the list of headers."""
    name_lower = name.lower()
    for header in headers:
        if header['name'].lower() == name_lower:
            return header['value']
    return None

def decode_part_body(part):
    """Decodes the body data from a message part."""
    body_data = part.get('body', {}).get('data')
    if body_data:
        # Gmail API returns base64url encoded data
        return base64.urlsafe_b64decode(body_data.encode('ASCII')).decode('utf-8', 'replace')
    return ""

def extract_text_and_links(payload):
    """Recursively extracts text content and links from message parts."""
    text_content = ""
    links = set()
    mime_type = payload.get('mimeType', '')
    parts = payload.get('parts')

    if parts:
        # Recursively process multipart messages
        for part in parts:
            part_text, part_links = extract_text_and_links(part)
            text_content += part_text + "\n"
            links.update(part_links)
    elif mime_type.startswith('text/'):
        body_text = decode_part_body(payload)
        if mime_type == 'text/html':
            try:
                soup = BeautifulSoup(body_text, 'html.parser')
                # Extract text
                text_content = soup.get_text(separator='\n', strip=True)
                # Extract links (href attributes)
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href'].strip()
                    if href and not href.startswith('#') and not href.startswith('mailto:'):
                         # Basic check to avoid internal links or mailto
                         links.add(href)
            except Exception as e:
                print(f"  Warning: Could not parse HTML content: {e}")
                text_content = body_text # Fallback to raw HTML text
        else: # text/plain or other text types
            text_content = body_text
            # Basic link extraction from plain text (less reliable)
            # This regex is simple, more complex ones exist
            found_links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text_content)
            links.update(link for link in found_links if len(link) > 4) # Basic sanity check

    return text_content, links

def analyze_attachments(payload):
    """Checks attachments for suspicious types."""
    suspicious_found = False
    parts = payload.get('parts', [])
    all_parts = [payload] + parts # Check main payload too, just in case

    def check_part(part):
        nonlocal suspicious_found
        filename = part.get('filename')
        mime_type = part.get('mimeType')
        # Check if 'attachmentId' exists, indicating it's likely an attachment
        if filename and part.get('body', {}).get('attachmentId'):
            print(f"  Attachment found: {filename} (Type: {mime_type})")
            # Check by extension
            _, ext = os.path.splitext(filename)
            if ext.lower() in BLOCKED_ATTACHMENT_EXTENSIONS:
                print(f"    ALERT: Blocked extension detected: {ext}")
                suspicious_found = True
            # Check by MIME type
            if mime_type.lower() in BLOCKED_ATTACHMENT_MIMETYPES:
                 print(f"    ALERT: Blocked MIME type detected: {mime_type}")
                 suspicious_found = True
        # Recursively check nested parts (though less common for direct attachments)
        if part.get('parts'):
            for sub_part in part.get('parts'):
                check_part(sub_part)

    # Start checking from the main payload level
    check_part(payload)

    return suspicious_found


def analyze_links(links):
    """Performs basic checks on extracted links."""
    suspicious_found = False
    if not links:
        return False

    print(f"  Analyzing {len(links)} links...")
    for link in links:
        try:
            parsed_url = urlparse(link)
            hostname = parsed_url.hostname
            if not hostname: continue # Skip invalid/relative links

            # 1. Check for IP address links
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
                print(f"    ALERT: Link uses IP address: {link}")
                suspicious_found = True
                continue # Don't need other checks for this link

            # 2. Check for known URL shorteners
            for shortener in KNOWN_URL_SHORTENERS:
                if hostname.endswith(shortener):
                    print(f"    ALERT: Link uses known shortener: {link}")
                    suspicious_found = True
                    break # Move to next link if shortener found
            if suspicious_found and hostname.endswith(shortener): continue

            # 3. Check TLD
            tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
            if tld in SUSPICIOUS_TLDS:
                 print(f"    ALERT: Link uses suspicious TLD '{tld}': {link}")
                 suspicious_found = True
                 continue

            # Add more checks? (e.g., excessive subdomains, lookalike characters - complex)

        except ValueError:
            print(f"    Warning: Could not parse URL: {link}")
        except Exception as e:
            print(f"    Warning: Error analyzing link {link}: {e}")

    return suspicious_found

def check_authentication(headers):
    """Parses Authentication-Results header for SPF/DKIM/DMARC failures."""
    auth_header = get_header(headers, 'Authentication-Results')
    auth_failed = False
    if auth_header:
        print(f"  Auth Results: {auth_header}")
        # Simple check for failures (adjust regex if needed for specific formats)
        # Look for anything other than 'pass' for spf, dkim, dmarc
        if re.search(r'spf=(?!pass\b)\w+', auth_header, re.IGNORECASE):
            print("    ALERT: SPF check did not pass.")
            auth_failed = True
        if re.search(r'dkim=(?!pass\b)\w+', auth_header, re.IGNORECASE):
            print("    ALERT: DKIM check did not pass.")
            auth_failed = True
        if re.search(r'dmarc=(?!pass\b)\w+', auth_header, re.IGNORECASE):
            print("    ALERT: DMARC check did not pass.")
            auth_failed = True
    else:
        # Also check ARC-Authentication-Results, common in forwarded mail
        arc_auth_header = get_header(headers, 'ARC-Authentication-Results')
        if arc_auth_header:
             print(f"  ARC Auth Results: {arc_auth_header}")
             # Simplified check similar to above - focus on the final verdict if possible
             if re.search(r'spf=(?!pass\b)\w+', arc_auth_header, re.IGNORECASE) or \
                re.search(r'dkim=(?!pass\b)\w+', arc_auth_header, re.IGNORECASE) or \
                re.search(r'dmarc=(?!pass\b)\w+', arc_auth_header, re.IGNORECASE):
                 print("    ALERT: ARC results indicate potential auth failure in chain.")
                 # Treat ARC failure cautiously, might be due to forwarding chain issues
                 # Depending on policy, you might handle this differently than direct failure
                 auth_failed = True # Mark as failed for this basic check
        else:
            print("  No Authentication-Results or ARC header found.")
            # Decide how to treat missing headers. Could be slightly suspicious.
            # auth_failed = True # Optionally flag missing headers

    return auth_failed

def check_impersonation(headers):
    """Basic check for display name spoofing against internal names/domains."""
    from_header = get_header(headers, 'From')
    if not from_header: return False

    try:
        display_name, email_address = parseaddr(from_header)
        if not display_name or not email_address:
            return False # Malformed or simple address

        print(f"  Checking 'From': Name='{display_name}', Address='{email_address}'")
        _ , sender_domain = email_address.split('@', 1)
        sender_domain = sender_domain.lower()

        # Check if domain is EXTERNAL but display name looks INTERNAL
        if sender_domain not in INTERNAL_DOMAINS:
            name_lower = display_name.lower()
            for internal_name_pattern in IMPORTANT_INTERNAL_NAMES:
                if internal_name_pattern.lower() in name_lower:
                    print(f"    ALERT: Potential Impersonation! External domain '{sender_domain}' used with internal-looking name '{display_name}'.")
                    return True
        else:
             print(f"    Sender domain '{sender_domain}' is internal or not checked for impersonation.")


    except Exception as e:
        print(f"    Warning: Could not parse 'From' header for impersonation check: {e}")

    return False


def check_keywords(text_content):
    """Checks body text for suspicious keywords."""
    if not text_content: return False
    text_lower = text_content.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            print(f"    ALERT: Found suspicious keyword: '{keyword}'")
            return True
    return False

def apply_labels_and_mark_read(service, message_id, label_ids_to_add):
    """Adds specified labels and removes the 'UNREAD' label."""
    # Always remove UNREAD label when processing
    modify_request = {
        'addLabelIds': list(set(label_ids_to_add)), # Ensure unique IDs
        'removeLabelIds': ['UNREAD']
    }
    if not label_ids_to_add:
         print(f"  No specific indicator labels to add for {message_id}. Marking as read only.")

    try:
        service.users().messages().modify(
            userId='me',
            id=message_id,
            body=modify_request
        ).execute()
        added_str = f"Added: {label_ids_to_add}" if label_ids_to_add else "Added: None"
        print(f"  Message ID: {message_id} processed. {added_str}, Removed: ['UNREAD']")
        return True # Indicate success
    except HttpError as error:
        if error.resp.status == 429:
            print(f"  Rate limit exceeded for message {message_id}. Waiting and will retry later...")
            time.sleep(5)
            return False # Indicate failure (will likely be retried on next script run)
        print(f"  An error occurred modifying message {message_id}: {error}")
        return False
    except Exception as e:
        print(f"  An unexpected error modifying message {message_id}: {e}")
        return False


# --- Main Execution ---
if __name__ == '__main__':
    print("Starting Enhanced Gmail Sorter Script...")
    service = get_gmail_service()

    if not service:
        print("Could not get Gmail service. Exiting.")
        exit()

    processed_message_ids = load_processed_ids()
    print(f"Loaded {len(processed_message_ids)} previously processed email IDs.")

    # --- Pre-fetch/Create Label IDs ---
    label_id_cache = {}
    required_labels = [
        LABEL_AUTH_FAIL, LABEL_SUSPICIOUS_LINK, LABEL_SUSPICIOUS_ATTACHMENT,
        LABEL_SUSPICIOUS_KEYWORD, LABEL_IMPERSONATION_FLAG, LABEL_NEEDS_REVIEW
    ]
    print("Fetching/Verifying Label IDs...")
    all_labels_ok = True
    for label_name in required_labels:
        if not get_label_id(service, label_name, label_id_cache):
            print(f"FATAL: Could not get or create label '{label_name}'. Exiting.")
            all_labels_ok = False
            # Depending on severity, you might want to exit or just skip applying this label
    if not all_labels_ok: exit()

    print("\nStarting email processing (checking for phishing indicators)...")
    newly_processed_count = 0
    try:
        page_token = None
        while True:
            try:
                list_response = service.users().messages().list(
                    userId='me',
                    labelIds=['INBOX', 'UNREAD'],
                    maxResults=50, # Process smaller batches due to increased processing per email
                    pageToken=page_token
                ).execute()
                messages = list_response.get('messages', [])

                if not messages:
                    print("No more unread messages found.")
                    break

                print(f"\nFetched {len(messages)} unread messages...")

                for message_summary in messages:
                    message_id = message_summary['id']
                    if message_id in processed_message_ids:
                        # print(f"Skipping already processed message ID: {message_id}")
                        continue

                    print(f"\nProcessing message ID: {message_id}")
                    indicator_labels_to_add = set() # Use a set to avoid duplicate labels
                    try:
                        # Get FULL message details (needed for body, attachments)
                        message_details = service.users().messages().get(
                            userId='me',
                            id=message_id,
                            format='full' # Changed from 'metadata'
                        ).execute()

                        headers = message_details.get('payload', {}).get('headers', [])
                        payload = message_details.get('payload', {})

                        # 1. Check Authentication
                        if check_authentication(headers):
                            indicator_labels_to_add.add(label_id_cache[LABEL_AUTH_FAIL.lower()])

                        # 2. Extract Text and Links from Body
                        # This needs careful handling of multipart messages
                        body_text, links = extract_text_and_links(payload)
                        # print(f"  Extracted ~{len(body_text)} chars of text and {len(links)} links.")

                        # 3. Check Keywords
                        if check_keywords(body_text):
                             indicator_labels_to_add.add(label_id_cache[LABEL_SUSPICIOUS_KEYWORD.lower()])

                        # 4. Analyze Links
                        if analyze_links(links):
                             indicator_labels_to_add.add(label_id_cache[LABEL_SUSPICIOUS_LINK.lower()])

                        # 5. Analyze Attachments
                        if analyze_attachments(payload):
                             indicator_labels_to_add.add(label_id_cache[LABEL_SUSPICIOUS_ATTACHMENT.lower()])

                        # 6. Check Impersonation
                        if check_impersonation(headers):
                             indicator_labels_to_add.add(label_id_cache[LABEL_IMPERSONATION_FLAG.lower()])


                        # --- Final Decision ---
                        final_labels_to_add = list(indicator_labels_to_add)
                        num_indicators = len(indicator_labels_to_add)
                        print(f"  Found {num_indicators} indicators.")

                        if num_indicators >= MIN_INDICATORS_FOR_REVIEW:
                            print(f"  Threshold reached. Adding '{LABEL_NEEDS_REVIEW}' label.")
                            final_labels_to_add.append(label_id_cache[LABEL_NEEDS_REVIEW.lower()])

                        # Apply labels and mark as read
                        success = apply_labels_and_mark_read(service, message_id, final_labels_to_add)

                        if success:
                           processed_message_ids.add(message_id)
                           newly_processed_count += 1
                        else:
                            print(f"  Modification failed for {message_id}, will likely retry on next run.")


                    except HttpError as error:
                        print(f"  Error fetching/processing details for message {message_id}: {error}")
                        if error.resp.status == 404:
                             print(f"  Message {message_id} not found (maybe deleted?). Skipping.")
                             processed_message_ids.add(message_id) # Mark as processed to avoid retrying
                        # Add more specific error handling if needed
                    except Exception as e:
                        print(f"  Unexpected error processing message {message_id}: {e}")
                        # Optionally add to processed_ids to prevent infinite loops on problematic emails
                        # processed_message_ids.add(message_id)

                    # Optional: Add a small delay to avoid hitting rate limits
                    time.sleep(0.5) # Increased delay due to more processing

                page_token = list_response.get('nextPageToken')
                if not page_token:
                    break

            except HttpError as error:
                print(f"An error occurred listing messages: {error}")
                if error.resp.status == 429:
                    print("Rate limit exceeded while listing messages. Waiting 15 seconds...")
                    time.sleep(15)
                    continue
                else:
                    print("Aborting due to unhandled API error during listing.")
                    break
            except Exception as e:
                 print(f"An unexpected error occurred during message listing/batch processing: {e}")
                 break

    finally:
        if newly_processed_count > 0:
            print(f"\nProcessed {newly_processed_count} new emails in this run.")
            print(f"Saving updated list of {len(processed_message_ids)} processed email IDs...")
            save_processed_ids(processed_message_ids)
        else:
            print("\nNo new emails were processed in this run.")

    print("\nEnhanced Gmail sorter script finished.")