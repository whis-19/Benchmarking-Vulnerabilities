from urllib.parse import urlparse
import re
import idna  # Import the idna library

ALLOWED_SCHEMES = ["http", "https"]
ALLOWED_DOMAINS = ["example.com", "localhost"]  # Replace with your allowed domains

def validate_url(url):
    try:
        result = urlparse(url)
        if result.scheme not in ALLOWED_SCHEMES:
            return False

        netloc = result.netloc.lower()  # Convert to lowercase

        # Check if the netloc ends with any of the allowed domains
        is_valid_domain = any(netloc.endswith("." + domain) or netloc == domain for domain in ALLOWED_DOMAINS)

        if not is_valid_domain:
            return False

        return True
    except:
        return False

# Example usage and testing
urls_to_test = [
    "http://example.com",
    "https://example.com",
    "http://evil.example.com",  # Subdomain - now blocked
    "http://example.com.evil.com", # Suffix - now blocked
    "http://Example.com",  # Case sensitivity - now blocked
    "http://localhost",
    "http://localhost:8000",
    "ftp://example.com",  # Invalid scheme
    "http://anotherdomain.com", # Invalid domain
    "http://exаmple.com", # Homograph - still vulnerable, needs IDN handling
]

for url in urls_to_test:
    is_valid = validate_url(url)
    print(f"URL: {url}, Valid: {is_valid}")

