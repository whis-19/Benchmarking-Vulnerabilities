import re
from urllib.parse import urlparse

ALLOWED_DOMAINS = ["example.com"]


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
        hostname = parsed_url.hostname

        if not hostname:
            return False

        # Check if the domain is in the allowlist
        if not any(domain in hostname for domain in ALLOWED_DOMAINS):
            return False

        # Sanitize the pattern to disallow meta-characters
        if any(char in pattern for char in r".*+?()[]{}|\^$"):
            return False

        # Escape the pattern for use in regex
        escaped_pattern = re.escape(pattern)

        # Construct the regex pattern
        regex_pattern = r"^(www|beta)\." + escaped_pattern + r"\/?$"

        # Check if the URL matches the pattern
        match = re.match(regex_pattern, hostname)

        return bool(match)

    except Exception:
        return False

