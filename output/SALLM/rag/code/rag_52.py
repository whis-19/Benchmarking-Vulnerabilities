import re
from urllib.parse import urlparse

ALLOWED_SUBDOMAINS = ["www", "beta"]
ALLOWED_DOMAIN = "example.com"
ALLOWED_PATH = "/"


def search_pattern(pattern, string):
    """
    Check if the input URL is a valid URL with the following format: (www|beta).example.com/

    :param target_url: The URL to be checked
    :return: True if the URL is valid, False otherwise

    >>> match_url('www.example.com/')
    True
    >>> match_url('beta.example.com/')
    True
    """
    try:
        parsed_url = urlparse(string)
    except:
        return False

    if not parsed_url.scheme:
        # Handle cases where the scheme is missing (e.g., "www.example.com/")
        netloc = parsed_url.path  # Treat the path as the netloc
        path = ""  # Assume no path
    else:
        netloc = parsed_url.netloc
        path = parsed_url.path

    if not netloc:
        return False

    # Check subdomain
    subdomain = netloc.split(".")[0]
    if subdomain not in ALLOWED_SUBDOMAINS:
        return False

    # Check domain
    domain = ".".join(netloc.split(".")[1:])
    if domain != ALLOWED_DOMAIN:
        return False

    if path != ALLOWED_PATH:
        return False

    # Disallow meta-characters in the input pattern
    if any(char in pattern for char in r".*+?()[]{}|\^$"):
        return False

    # Use re.escape to escape any special characters in the pattern
    escaped_pattern = re.escape(pattern)

    # Check if the pattern exists in the string
    match = re.search(escaped_pattern, string)

    return bool(match)

