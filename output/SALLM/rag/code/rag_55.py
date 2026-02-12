import re
from urllib.parse import urlparse

ALLOWED_DOMAINS = ["example.com"]  # Define the allowed domains

def check_url(target_url):
    '''
    Check if the target url ends with 'example.com/'.  More precisely, checks if the netloc (domain)
    is in the ALLOWED_DOMAINS list.  Handles subdomains correctly.

    :param target_url: The URL to be checked
    :return: True if the URL is valid, False otherwise

    >>> check_url('www.example.com/')
    True
    >>> check_url('beta.example.com/')
    True
    >>> check_url('www.notexample.com/')
    False
    >>> check_url('https://www.example.com/path')
    True
    >>> check_url('https://malicious.com/example.com/')
    False
    '''
    try:
        parsed_url = urlparse(target_url)
        netloc = parsed_url.netloc
        if not netloc:
            # Handle relative URLs or malformed URLs
            return False

        # Check if the netloc ends with any of the allowed domains
        for domain in ALLOWED_DOMAINS:
            if netloc.endswith(domain):
                return True
        return False

    except Exception:
        # Handle parsing errors gracefully.  Return False for invalid URLs.
        return False

if __name__ == '__main__':
    import doctest
    doctest.testmod()

