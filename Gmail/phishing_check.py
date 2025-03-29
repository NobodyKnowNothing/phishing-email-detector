
PHISHING_KEYWORDS = [
    "access", "accounts", "auth", "security", "portal", "user", "company", "admin",
    "credential", "identity", "login", "password", "privilege", "token", "validation",
    "assurance", "availability", "confidentiality", "integrity", "privacy", "safety",
    "trust", "verification", "check", "key", "lock", "biometrics", "authorize",
    "authentication", "session", "verification", "profile", "service", "support",
    "notify", "email", "account", "update", "secure", "notification", "transaction",
    "validate", "confirmation", "manager", "assistant", "dashboard", "information",
    "communication", "finance", "maintenance", "service", "customer", "invoice",
    "billing", "transaction", "subscription", "order", "shipment", "purchase",
    "support", "notification", "alert", "confirmation", "update", "information",
    "communication", "finance", "billinginfo", "receipt", "accountinfo", "profile",
    "payment", "invoiceinfo", "orderinfo"
]
global PHISHING_LINKS

def import_data():
    global PHISHING_LINKS

    with open('Data/phishing-links-NEW-today.txt', 'r') as file:
        PHISHING_LINKS = [PHISHING_LINKS.strip() for PHISHING_LINKS in file if PHISHING_LINKS.strip()]

def check_key_words(email_item):
    body = email_item['body']
    subject = email_item['subject']

    text_lower = body.lower()
    found = [word for word in PHISHING_KEYWORDS if word in text_lower]
    return len(found)

def check_link(link):
    global PHISHING_LINKS
    text_lower = link.lower()
    for plink in PHISHING_LINKS:
        if(link == plink):
            return 10
        
def check_dmarc(email_item):
    if(email_item["dmarc"] == ['dmarc=pass']):
        return 0
    if(email_item["dmarc"] == None):
        return 2
    return 7

def check_spf(email_item):
    if(email_item["spf"][:4] == "pass"):
        return 0
    elif(email_item["spf"] == None):
        return 2
    else:
        return 7
def check_dkim(email_item):
    if(email_item["dkim"] == ['dkim=pass']):
        return 0
    if(email_item["dkim"] == None):
        return 2
    return 7 
    
def check_all_links(email_item):
    
    pass
        