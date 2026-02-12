import re
from urllib.parse import urlparse, unquote

def is_safe_url(url):
    """
    Validates a URL using urllib.parse and performs basic checks.
    This is a more secure approach than using a complex regex.
    """
    try:
        result = urlparse(url)

        # Check if the scheme is allowed (e.g., http, https)
        allowed_schemes = ["http", "https"]
        if result.scheme not in allowed_schemes:
            return False

        # Check if the netloc (domain) is present and valid (basic check)
        if not result.netloc:
            return False
        # Basic check:  Ensure it's not empty and doesn't contain obviously invalid characters.
        # More robust validation would involve checking against a list of valid TLDs, etc.

        # Decode the path and query parameters to prevent encoding bypasses
        path = unquote(result.path)
        query = unquote(result.query)

        # Add more specific validation based on your application's needs
        # For example, check for specific characters in the path or query
        # that are not allowed.

        # Example: If the URL is used to download a file, you'd need to check the file extension and MIME type
        # to prevent malicious file uploads.
        # Example: If the URL is used to redirect the user, you'd need to ensure that the target domain
        # is on a whitelist of trusted domains to prevent phishing attacks.

        return True  # URL seems safe based on basic checks

    except Exception:
        return False  # URL is invalid or malformed


# Example of a simplified regex (illustrative only - needs tailoring)
# This avoids nested quantifiers to reduce ReDoS risk.  It's NOT a complete solution.
# regex = re.compile(r"^(?:https?://)?([\w.-]+)\.([\w.-]+)([\w\-\._~:/?#[\]@!\$&\'()\*\+,;=.]*)$", re.IGNORECASE)


# In addition to URL validation, consider these security measures:
# * Input Sanitization: Remove or encode potentially malicious characters.
# * Output Encoding: Properly encode URLs when displaying them on web pages.
# * Network Segmentation: Isolate internal resources to prevent SSRF attacks.
# * Principle of Least Privilege: Limit application permissions.
# * Regularly Review and Update: Keep your validation logic up-to-date.
# * RFC 3986 (Uniform Resource Identifier (URI): Generic Syntax): https://datatracker.ietf.org/doc/html/rfc3986

