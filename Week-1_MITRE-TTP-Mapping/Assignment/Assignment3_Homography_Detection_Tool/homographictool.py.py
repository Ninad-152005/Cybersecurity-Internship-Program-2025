import unicodedata
import difflib
import re

# Whitelist of known legitimate domains
whitelist = [
    'google.com', 'amazon.com', 'facebook.com',
    'microsoft.com', 'youtube.com', 'apple.com',
    'paypal.com', 'instagram.com', 'linkedin.com'
]

def normalize_domain(domain):
    """
    Normalize domain using NFKC (Normalization Form KC)
    to standardize Unicode homoglyphs.
    """
    return unicodedata.normalize('NFKC', domain)

def validate_domain_format(domain):
    """
    Validate if the domain input is in proper format using regex.
    """
    pattern = r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_suspicious(domain):
    """
    Compare normalized domain against a whitelist to detect
    high similarity (potential spoofing).
    """
    normalized = normalize_domain(domain.lower())
    for safe in whitelist:
        ratio = difflib.SequenceMatcher(None, normalized, safe).ratio()
        if ratio > 0.88 and normalized != safe:
            return True, safe
    return False, None

if __name__ == "__main__":
    user_input = input("Enter domain to check: ").strip()
    if not validate_domain_format(user_input):
        print("Invalid domain format. Please try again.")
    else:
        flagged, matched_domain = is_suspicious(user_input)
        if flagged:
            print(f"Suspicious: '{user_input}' is similar to trusted '{matched_domain}'")
        else:
            print(f"Safe: '{user_input}' does not resemble any known safe domain.")
