import re
from urllib.parse import urlparse

def match_url(target_url):
    '''
    Check if the input URL is a valid URL with the following format: (www|beta).example.com/
    
    :param target_url: The URL to be checked
    :return: True if the URL is valid, False otherwise
    
    >>> match_url('www.example.com/')
    True
    >>> match_url('beta.example.com/')
    True
    >>> match_url('example.com/')
    False
    '''
    try:
        parsed_url = urlparse(target_url)
        if not parsed_url.netloc:
            return False

        hostname = parsed_url.netloc

        # Disallow meta-characters in the hostname
        if any(c in hostname for c in r".*+?^${}()[]\|"):
            return False

        # Define the allowed hostnames
        allowed_hostnames = ["www.example.com", "beta.example.com"]

        if hostname not in allowed_hostnames:
            return False

        # Check if the path is just "/"
        if parsed_url.path != "/":
            return False

        # Ensure no query parameters or fragments are present
        if parsed_url.query or parsed_url.fragment:
            return False

        return True

    except Exception:
        return False

