import os
import re
import tldextract
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

# Hardcoded list of allowed domains (most secure)
HARDCODED_ALLOWED_DOMAINS = ["example.com", "localhost", "trusted.com"]

ALLOWED_DOMAINS_STRING = os.environ.get("ALLOWED_DOMAINS")  # Get without default

if ALLOWED_DOMAINS_STRING is None:
    logging.warning("ALLOWED_DOMAINS environment variable not set. Using default: example.com,localhost")
    ALLOWED_DOMAINS_STRING = "example.com,localhost"

# Split the string and strip whitespace
ALLOWED_DOMAINS = [domain.strip() for domain in ALLOWED_DOMAINS_STRING.split(",")]

def is_valid_domain(domain):
    """
    Validates a domain name using tldextract and a regular expression.
    """
    try:
        ext = tldextract.extract(domain)
        if not ext.suffix or not ext.domain:
            logging.warning(f"Domain '{domain}' is invalid: Invalid domain format (tldextract failed).")
            return False  # Invalid domain format

        # Check against hardcoded list
        if domain not in HARDCODED_ALLOWED_DOMAINS:
            logging.warning(f"Domain '{domain}' is invalid: Not in hardcoded whitelist.")
            return False

        # Further validation with regex (optional, but recommended)
        # More robust regex (example - still not perfect for all IDNs)
        domain_regex = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
        if not re.match(domain_regex, domain):
            logging.warning(f"Domain '{domain}' is invalid: Regex validation failed.")
            return False

        return True
    except Exception as e:
        logging.exception(f"Domain '{domain}' validation failed with exception: {e}")
        return False  # Handle any exceptions during validation

# Example usage:
for domain in ALLOWED_DOMAINS:
    if is_valid_domain(domain):
        logging.info(f"Domain '{domain}' is valid.")
    else:
        logging.error(f"Domain '{domain}' is INVALID!")
        # Handle invalid domain appropriately (e.g., log an error, reject the input)
        # Potentially raise an exception or terminate the application if critical

