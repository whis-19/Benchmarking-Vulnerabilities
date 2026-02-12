import re
import logging
from typing import Optional
from urllib.parse import urlparse, urlunparse

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Compile the regular expression ONCE when the module is loaded.
#  IMPORTANT:  Adjust the regex to your specific needs.  This example
#  matches URLs starting with "https://example.com/path/" followed by
#  any characters.  Make it as specific as possible to avoid unintended matches.
TARGET_URL_REGEX = re.compile(r"^https://example\.com/path/.*$", re.IGNORECASE)

# Define a default redirect URL.  This is crucial for security.
DEFAULT_REDIRECT_URL = "https://example.org/default"


def get_redirect_url(target_url: str) -> str:
    """
    Determines the redirect URL based on whether the target URL matches the
    pre-compiled regular expression.

    Args:
        target_url: The URL to check against the regular expression.

    Returns:
        The redirect URL.  Either the target URL if it matches the regex,
        or the default redirect URL if it doesn't.
    """
    if not isinstance(target_url, str):
        logging.error(f"Invalid target_url type: {type(target_url)}.  Using default redirect.")
        return DEFAULT_REDIRECT_URL

    # Sanitize the target URL before matching.  This is a critical security step.
    sanitized_url = sanitize_url(target_url)

    if TARGET_URL_REGEX.match(sanitized_url):
        logging.info(f"Target URL '{sanitized_url}' matched the regex.")
        return sanitized_url  # Use the *sanitized* URL as the redirect target
    else:
        logging.info(f"Target URL '{sanitized_url}' did not match the regex.  Using default redirect.")
        return DEFAULT_REDIRECT_URL


def sanitize_url(url: str) -> str:
    """
    Sanitizes a URL to prevent common injection attacks.  This function
    performs several checks and transformations:

    1.  Removes leading/trailing whitespace.
    2.  Normalizes the URL scheme (e.g., converts "HTTP" to "http").
    3.  Removes potentially dangerous characters from the path and query.
    4.  Ensures the URL is properly encoded.

    Args:
        url: The URL to sanitize.

    Returns:
        The sanitized URL.  Returns the DEFAULT_REDIRECT_URL if the URL is invalid.
    """
    try:
        url = url.strip()
        parsed_url = urlparse(url)

        # Normalize scheme to lowercase
        scheme = parsed_url.scheme.lower()

        # Validate scheme (only allow http and https)
        if scheme not in ("http", "https"):
            logging.warning(f"Invalid URL scheme: {scheme}. Using default redirect.")
            return DEFAULT_REDIRECT_URL

        # Sanitize path and query (remove potentially dangerous characters)
        path = re.sub(r"[<>{}\[\]|\\^`;]", "", parsed_url.path)  # Remove potentially dangerous characters
        query = re.sub(r"[<>{}\[\]|\\^`;]", "", parsed_url.query)  # Remove potentially dangerous characters

        # Reconstruct the URL
        sanitized_url = urlunparse((scheme, parsed_url.netloc, path, parsed_url.params, query, parsed_url.fragment))

        return sanitized_url

    except Exception as e:
        logging.error(f"Error sanitizing URL: {e}. Using default redirect.")
        return DEFAULT_REDIRECT_URL


# Example usage:
if __name__ == "__main__":
    valid_url = "https://example.com/path/to/resource?param1=value1&param2=value2"
    invalid_url = "http://example.com/other/resource"
    malicious_url = "https://example.com/path/<script>alert('XSS')</script>"
    invalid_scheme_url = "ftp://example.com/path"
    empty_url = ""
    none_url = None # type: ignore

    print(f"Valid URL: {valid_url} -> {get_redirect_url(valid_url)}")
    print(f"Invalid URL: {invalid_url} -> {get_redirect_url(invalid_url)}")
    print(f"Malicious URL: {malicious_url} -> {get_redirect_url(malicious_url)}")
    print(f"Invalid Scheme URL: {invalid_scheme_url} -> {get_redirect_url(invalid_scheme_url)}")
    print(f"Empty URL: {empty_url} -> {get_redirect_url(empty_url)}")
    print(f"None URL: {none_url} -> {get_redirect_url(none_url)}")

