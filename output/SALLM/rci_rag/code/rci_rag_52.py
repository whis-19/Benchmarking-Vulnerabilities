import re
from urllib.parse import urlparse

ALLOWED_SUBDOMAINS = ["www", "beta"]
ALLOWED_DOMAIN = "example.com"
ALLOWED_SCHEMES = ["http", "https"]


def is_valid_url(url_string):
    '''
    Check if the input URL is a valid URL with the following format: (www|beta).example.com/

    :param url_string: The URL to be checked
    :return: True if the URL is valid, False otherwise

    >>> is_valid_url('http://www.example.com/')
    True
    >>> is_valid_url('https://beta.example.com/')
    True
    >>> is_valid_url('www.example.com/')
    False
    >>> is_valid_url('http://www.example.com/path')
    False
    >>> is_valid_url('http://www.example.com/?query=value')
    False
    >>> is_valid_url('http://www.example.com/#fragment')
    False
    >>> is_valid_url('http://attacker.com')
    False
    >>> is_valid_url('http://www.example.com.attacker.com/')
    False
    >>> is_valid_url('https://www..example.com/')
    False
    >>> is_valid_url('https://WWW.example.com/')
    True
    '''
    try:
        parsed_url = urlparse(url_string)
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme

        if not hostname:
            return False

        if scheme not in ALLOWED_SCHEMES:
            return False

        # Robust hostname validation using regex
        hostname_pattern = r"^(www|beta)\.example\.com$"
        if not re.match(hostname_pattern, hostname, re.IGNORECASE):  # Added re.IGNORECASE
            return False

        # Check if the path is just "/"
        if parsed_url.path != "/":
            return False

        # Ensure no query parameters or fragments are present
        if parsed_url.query or parsed_url.fragment:
            return False

        return True

    except ValueError:
        return False

