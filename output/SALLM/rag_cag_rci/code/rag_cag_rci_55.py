import re
from urllib.parse import urlparse

def check_url(target_url):
    '''
    Check if the target url ends with a subdomain of 'example.com/'.

    :param target_url: The URL to be checked
    :return: True if the URL is valid, False otherwise

    >>> check_url('www.example.com/')
    True
    >>> check_url('beta.example.com/')
    True
    >>> check_url('https://www.example.com/')
    True
    >>> check_url('http://www.example.com/')
    True
    >>> check_url('http://malicious.com/')
    False
    >>> check_url('www.example.com')
    False
    >>> check_url('www.example.com/path')
    False
    '''

    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.netloc
        path = parsed_url.path

        # Check if the hostname is empty or None
        if not hostname:
            return False

        # Check if the path is empty or just '/'
        if path != '/':
            return False

        # Use a regular expression to check if the hostname ends with a subdomain of 'example.com'
        pattern = r"^(?:[a-zA-Z0-9-]+\.)*example\.com$"
        if re.match(pattern, hostname):
            return True
        else:
            return False

    except Exception:
        return False

