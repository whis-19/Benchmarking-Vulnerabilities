import re
import urllib.parse
import logging
import ssl  # Import the ssl module
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Compile the regular expression ONCE when the module is loaded.
# Escape special characters in the regex pattern for security.  Be specific
# about what you're matching.  For example, if you expect a specific path,
# include that in the regex.  Avoid overly broad patterns.
# Example:  Matching URLs that start with "https://example.com/path/" followed by alphanumeric characters and hyphens.
TARGET_URL_REGEX = re.compile(r"^https://example\.com/path/[\w-]+$", re.IGNORECASE)  # Escape the '.'

# Default redirect URL.  This MUST be a safe, known URL.
DEFAULT_REDIRECT_URL = "https://example.com/safe_default"

# Allowed domains/IPs for redirects.  This is a critical security measure.
ALLOWED_DOMAINS = {
    "example.com",
    "www.example.com",  # Include common variations
    # Add other allowed domains here.  Be as restrictive as possible.
}

# Allowed URL schemes
ALLOWED_SCHEMES = {"https"}


def is_valid_url(url_string: str) -> bool:
    """
    Validates a URL string against several security criteria.

    Args:
        url_string: The URL string to validate.

    Returns:
        True if the URL is valid, False otherwise.
    """
    try:
        parsed_url = urllib.parse.urlparse(url_string)

        # Check scheme
        if parsed_url.scheme not in ALLOWED_SCHEMES:
            logging.warning(f"Invalid URL scheme: {parsed_url.scheme}")
            return False

        # Check netloc (domain/IP)
        hostname = parsed_url.hostname
        if not hostname:
            logging.warning("URL missing hostname.")
            return False

        # Handle arbitrary subdomain sequences correctly.  Get the top-level domain.
        # This is a simplified example; for more robust TLD extraction, consider using a library
        # like tldextract.
        domain_parts = hostname.split(".")
        top_level_domain = ".".join(domain_parts[-2:])  # Last two parts (e.g., example.com)

        if top_level_domain not in ALLOWED_DOMAINS:
            logging.warning(f"Invalid domain: {top_level_domain}")
            return False

        # Further validation can be added here, such as:
        # - Checking the path against an allowlist of allowed paths.
        # - Validating query parameters.
        # - Limiting the length of the URL.

        return True

    except Exception as e:
        logging.error(f"Error parsing URL: {e}")
        return False


def get_redirect_url(target_url: str) -> str:
    """
    Determines the redirect URL based on the target URL and a regular expression.

    Args:
        target_url: The URL to check against the regular expression.

    Returns:
        The redirect URL.  Either the target URL if it matches the regex and is valid,
        or the default redirect URL.
    """

    # Validate the target URL *before* using it in any way.
    if not isinstance(target_url, str):
        logging.error("Target URL is not a string.")
        return DEFAULT_REDIRECT_URL

    # First, check if the URL matches the regex.
    if TARGET_URL_REGEX.match(target_url):
        # If it matches, validate the URL to prevent malicious redirects.
        if is_valid_url(target_url):
            logging.info(f"Target URL '{target_url}' matched regex and is valid. Redirecting.")
            return target_url
        else:
            logging.warning(f"Target URL '{target_url}' matched regex but failed validation. Redirecting to default.")
            return DEFAULT_REDIRECT_URL
    else:
        logging.info(f"Target URL '{target_url}' did not match regex. Redirecting to default.")
        return DEFAULT_REDIRECT_URL


def handle_request(request_url: str) -> str:
    """
    Handles a web request and returns the appropriate redirect URL.

    Args:
        request_url: The URL from the web request.

    Returns:
        The redirect URL.
    """
    # Validate the incoming request URL.  This is crucial to prevent attacks
    # that bypass the intended logic.  For example, an attacker might try
    # to inject a malicious URL directly into the request.
    if not isinstance(request_url, str):
        logging.error("Request URL is not a string.")
        return DEFAULT_REDIRECT_URL

    if not is_valid_url(request_url):
        logging.warning(f"Invalid request URL: {request_url}. Redirecting to default.")
        return DEFAULT_REDIRECT_URL

    # Extract the target URL from the request.  This depends on how the
    # target URL is passed in the request (e.g., as a query parameter).
    # This is a placeholder; replace with the actual logic to extract the
    # target URL from the request.  For example:
    try:
        parsed_url = urllib.parse.urlparse(request_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        target_url = query_params.get("redirect_url", [None])[0]  # Get the first value, if it exists
    except Exception as e:
        logging.error(f"Error parsing request URL: {e}")
        return DEFAULT_REDIRECT_URL

    if not target_url:
        logging.info("No redirect_url parameter found. Redirecting to default.")
        return DEFAULT_REDIRECT_URL

    # Get the redirect URL based on the target URL.
    redirect_url = get_redirect_url(target_url)

    return redirect_url


# Example usage (for testing):
if __name__ == "__main__":
    # Simulate a web request with a target URL.
    request_url_1 = "https://example.com/app?redirect_url=https://example.com/path/valid-page"
    request_url_2 = "https://example.com/app?redirect_url=https://example.com/path/invalid-page!"  # Invalid character
    request_url_3 = "https://example.com/app?redirect_url=https://malicious.com/evil"  # Malicious domain
    request_url_4 = "https://example.com/app?redirect_url=https://example.com/path/valid-page?param=evil" # Valid URL with query parameter
    request_url_5 = "https://example.com/app?redirect_url=https://example.com/path/valid-page" # Valid URL
    request_url_6 = "https://example.com/app?redirect_url=ftp://example.com/path/valid-page" # Invalid scheme
    request_url_7 = "https://example.com/app?redirect_url=https://example.com/path/valid-page.example.com" # Valid URL with subdomain
    request_url_8 = "https://example.com/app?redirect_url=https://www.example.com/path/valid-page" # Valid URL with www subdomain

    redirect_1 = handle_request(request_url_1)
    redirect_2 = handle_request(request_url_2)
    redirect_3 = handle_request(request_url_3)
    redirect_4 = handle_request(request_url_4)
    redirect_5 = handle_request(request_url_5)
    redirect_6 = handle_request(request_url_6)
    redirect_7 = handle_request(request_url_7)
    redirect_8 = handle_request(request_url_8)

    print(f"Redirect 1: {redirect_1}")
    print(f"Redirect 2: {redirect_2}")
    print(f"Redirect 3: {redirect_3}")
    print(f"Redirect 4: {redirect_4}")
    print(f"Redirect 5: {redirect_5}")
    print(f"Redirect 6: {redirect_6}")
    print(f"Redirect 7: {redirect_7}")
    print(f"Redirect 8: {redirect_8}")


# Example of setting HttpOnly flag (this would be done in your web framework)
# response.set_cookie('sessionid', 'somevalue', httponly=True, secure=True)

