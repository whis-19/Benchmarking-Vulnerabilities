import tldextract
import logging
from urllib.parse import urlparse, unquote, ParseError

logger = logging.getLogger(__name__)

# IMPORTANT: Replace with your actual allowed domains!
# Store this securely (e.g., in a configuration file or database).
ALLOWED_DOMAINS = {"example.com", "safe-domain.net"}  # Placeholder - REPLACE!


def is_url_safe(url):
    """
    Validates a URL against an allowlist of domains, allowing subdomains.

    Args:
        url: The URL to validate.

    Returns:
        True if the URL is safe, False otherwise.
    """
    try:
        url = url.rstrip('/')  # Remove trailing slash
        url = unquote(url)  # Decode URL-encoded characters
        parsed_url = urlparse(url)

        if parsed_url.scheme not in ("http", "https"):  # Only allow HTTP/HTTPS
            logger.warning(f"Invalid URL scheme: {parsed_url.scheme} for URL: {url}")
            return False

        # Use tldextract for more robust domain extraction
        ext = tldextract.extract(url)
        full_domain = f"{ext.domain}.{ext.suffix}".lower()  # Lowercase for normalization

        allowed = False
        for allowed_domain in ALLOWED_DOMAINS:
            # Allow exact matches or subdomains of allowed domains
            if full_domain == allowed_domain or full_domain.endswith("." + allowed_domain):
                allowed = True
                break

        if not allowed:
            logger.warning(f"URL domain not in allowlist: {full_domain} for URL: {url}")
            return False

        return True
    except ParseError as e:
        logger.error(f"Invalid URL format: {e}")
        return False
    except Exception as e:
        logger.exception(f"Unexpected error ({type(e).__name__}) validating URL: {e}")  # Log traceback and exception type
        return False

    # Consider clearing the tldextract cache periodically: tldextract.cache.clear()

