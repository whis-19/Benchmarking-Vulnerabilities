from urllib.parse import urlparse, urljoin

ALLOWED_DOMAINS = ["example.com", "www.example.com", "mysite.net"]  # Add your allowed domains

def validate_url(url):
    """
    Validates a URL to prevent open redirect vulnerabilities.
    """
    try:
        result = urlparse(url)

        # Check if the scheme is http or https
        if result.scheme not in ("http", "https"):
            return False

        # Check if the netloc (domain) is in the allowed list
        if result.netloc not in ALLOWED_DOMAINS:
            return False

        # Disallow relative URLs
        if not result.netloc:
            return False

        # Canonicalize the URL (basic example - use a more robust library in production)
        canonicalized_url = urljoin(url, ".")  # Removes trailing slashes and relative path segments

        # Re-parse the canonicalized URL to ensure it's still valid
        result = urlparse(canonicalized_url)

        # Double-check the scheme and netloc after canonicalization
        if result.scheme not in ("http", "https"):
            return False
        if result.netloc not in ALLOWED_DOMAINS:
            return False

        return True  # URL is valid
    except:
        return False  # URL is invalid (e.g., malformed)

