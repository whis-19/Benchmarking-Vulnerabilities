from urllib.parse import urljoin, urlparse
from flask import request  # Assuming Flask

ALLOWED_DOMAINS = {"example.com", "www.example.com"}  # Use a set for faster lookup
ALLOWED_PATHS = ("/profile/", "/settings/", "/help/") # Allowed URL prefixes

def is_safe_url(target):
    """Checks if a URL is safe to redirect to."""
    try:
        url = urljoin(request.host_url, target)
        parsed_url = urlparse(url)

        # Check scheme
        if parsed_url.scheme not in ('http', 'https'):
            return False

        # Check hostname against allow list
        if parsed_url.netloc not in ALLOWED_DOMAINS:
            return False

        # Check path against allow list
        if not any(url.startswith(urljoin(request.host_url, path)) for path in ALLOWED_PATHS):
            return False

        return True

    except ValueError:
        return False

