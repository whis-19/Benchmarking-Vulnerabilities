import tldextract
import socket
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

ALLOWED_DOMAINS = ["example.com", "api.example.com"]  # Example - MUST be securely managed

# Pre-populate tldextract cache
tldextract.extract("example.com")  # Force download of TLD list

def is_allowed_domain(url):
    """
    Checks if the domain in the URL is in the allowlist.  Uses tldextract for better domain handling.
    """
    try:
        # 1. Normalize the URL
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            logger.warning(f"URL {url} does not have a valid hostname.")
            return False

        # 2. Handle IP Addresses (Example: Reject them)
        try:
            socket.inet_aton(hostname)  # Check if it's a valid IP address
            logger.warning(f"URL {url} contains an IP address, which is not allowed.")
            return False
        except socket.error:
            pass  # It's not an IP address, continue

        # 3. Extract Domain
        extracted = tldextract.extract(hostname)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()  # Reconstruct and lowercase

        # 4. Check against allowlist (exact match only for this example)
        if domain in ALLOWED_DOMAINS:
            return True

        # No subdomain check in this example for increased security.  If needed, implement
        # explicit subdomain allowlisting.

        return False

    except (socket.gaierror, UnicodeDecodeError) as e:  # Specific exceptions
        logger.error(f"Error checking allowed domain for URL {url}: {e}")
        return False
    except Exception as e:
        logger.exception(f"Unexpected error checking allowed domain for URL {url}: {e}") # Log unexpected errors
        return False

