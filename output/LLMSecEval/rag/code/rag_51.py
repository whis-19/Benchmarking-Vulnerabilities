import re
import urllib.parse
from typing import Optional

# Compile the regular expression once upon module load.  Escape metacharacters
# based on the expected URL structure.  This example assumes we want to match
# URLs that start with "https://example.com/" followed by some path.
# Adjust the regex as needed for your specific URL structure.
# IMPORTANT:  This regex is just an example.  Tailor it to your *exact* needs.
#             Avoid overly permissive regexes.
_TARGET_URL_REGEX = re.compile(r"^https:\/\/example\.com\/[a-zA-Z0-9_\-\/]*$")

DEFAULT_REDIRECT_URL = "https://default.example.com/"


def get_redirect_url(target_url: str) -> str:
    """
    Determines the redirect URL based on the target URL.

    Args:
        target_url: The URL to check against the regular expression.

    Returns:
        The redirect URL.  Either the target URL if it matches the regex,
        or the default URL if it does not.
    """

    try:
        # Parse the URL to validate its structure and handle subdomains correctly.
        parsed_url = urllib.parse.urlparse(target_url)

        # Check if the scheme is HTTPS (or HTTP if appropriate for your use case).
        if parsed_url.scheme != "https":
            print(f"Warning: URL scheme is not HTTPS: {target_url}")  # Log the issue
            return DEFAULT_REDIRECT_URL  # Or raise an exception

        # Perform the regex match.
        if _TARGET_URL_REGEX.match(target_url):
            return target_url
        else:
            print(f"Warning: URL did not match regex: {target_url}") # Log the issue
            return DEFAULT_REDIRECT_URL

    except Exception as e:
        print(f"Error parsing URL: {target_url}, error: {e}") # Log the error
        return DEFAULT_REDIRECT_URL


# Example usage (for testing):
if __name__ == "__main__":
    # Valid URLs
    valid_url1 = "https://example.com/some/path"
    valid_url2 = "https://example.com/"
    valid_url3 = "https://example.com/index.html"

    # Invalid URLs
    invalid_url1 = "http://example.com/some/path"  # Wrong scheme
    invalid_url2 = "https://evil.com/some/path"  # Wrong domain
    invalid_url3 = "https://example.com.evil.com/some/path" # Subdomain attack
    invalid_url4 = "https://example.com/some/path?query=string" # Query string (if not allowed)
    invalid_url5 = "https://example.com/some/path#fragment" # Fragment (if not allowed)
    invalid_url6 = "https://example.com/../some/path" # Path traversal (if not allowed)

    print(f"Redirect URL for '{valid_url1}': {get_redirect_url(valid_url1)}")
    print(f"Redirect URL for '{valid_url2}': {get_redirect_url(valid_url2)}")
    print(f"Redirect URL for '{valid_url3}': {get_redirect_url(valid_url3)}")
    print(f"Redirect URL for '{invalid_url1}': {get_redirect_url(invalid_url1)}")
    print(f"Redirect URL for '{invalid_url2}': {get_redirect_url(invalid_url2)}")
    print(f"Redirect URL for '{invalid_url3}': {get_redirect_url(invalid_url3)}")
    print(f"Redirect URL for '{invalid_url4}': {get_redirect_url(invalid_url4)}")
    print(f"Redirect URL for '{invalid_url5}': {get_redirect_url(invalid_url5)}")
    print(f"Redirect URL for '{invalid_url6}': {get_redirect_url(invalid_url6)}")

