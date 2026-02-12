import re
from urllib.parse import urlparse

def is_valid_domain(domain):
    """Validates a domain name."""
    pattern = r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"
    return bool(re.match(pattern, domain))

ALLOWED_DOMAINS = ["example.com", "127.0.0.1"]  # Consider removing 127.0.0.1

def is_safe_url(target, app_host_url): # Added app_host_url parameter
    """
    Checks if a target URL is safe to redirect to, based on allowed domains.

    Args:
        target: The URL to check.
        app_host_url: The base URL of the application (e.g., "https://example.com").
                      This should be obtained from the application's configuration,
                      not directly from the request object if framework-agnosticism is desired.
    """
    ref_url = urlparse(app_host_url)
    test_url = urlparse(target)

    if test_url.scheme not in ('http', 'https'):
        return False

    if ref_url.netloc != test_url.netloc:
        return False

    if test_url.netloc not in ALLOWED_DOMAINS:
        return False

    # Additional validation to prevent subdomain bypass
    # Example: If ALLOWED_DOMAINS contains "127.0.0.1", then "127.0.0.1.example.com" will bypass this check.
    if not any(test_url.netloc == domain or test_url.netloc.endswith("." + domain) for domain in ALLOWED_DOMAINS):
        return False

    return True

