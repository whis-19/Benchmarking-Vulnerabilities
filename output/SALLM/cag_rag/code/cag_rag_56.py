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
        hostname = parsed_url.netloc
        path = parsed_url.path

        # Check if the scheme is present and is either http or https.  If not, reject.
        if not parsed_url.scheme or parsed_url.scheme not in ('http', 'https'):
            return False

        # Disallow meta-characters in the hostname.  This is the most secure approach
        # if we can get away with it.  If we *must* use regex, see the alternative
        # implementation below.
        if any(c in hostname for c in r".*+?()[]{}|^$\\"):
            return False

        # Check if the hostname matches the allowed pattern.  We are explicitly
        # checking for 'www.example.com' or 'beta.example.com'.  Any other
        # subdomain is rejected.
        if hostname not in ('www.example.com', 'beta.example.com'):
            return False

        # Check if the path is exactly '/'.  Anything else is rejected.
        if path != '/':
            return False

        return True

    except Exception:
        return False

# Alternative implementation using regex, if disallowing meta-characters
# is not feasible.  This is less secure, but may be necessary in some cases.
def match_url_regex(target_url):
    '''
    Check if the input URL is a valid URL with the following format: (www|beta).example.com/
    using regex.  This is less secure than the non-regex version.
    
    :param target_url: The URL to be checked
    :return: True if the URL is valid, False otherwise
    
    >>> match_url_regex('www.example.com/')
    True
    >>> match_url_regex('beta.example.com/')
    True
    >>> match_url_regex('example.com/')
    False
    '''
    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.netloc
        path = parsed_url.path

        # Check if the scheme is present and is either http or https.  If not, reject.
        if not parsed_url.scheme or parsed_url.scheme not in ('http', 'https'):
            return False

        # Escape the '.' character in the regex.  This is crucial for security.
        pattern = r"^(www|beta)\.example\.com$"

        if not re.match(pattern, hostname):
            return False

        # Check if the path is exactly '/'.  Anything else is rejected.
        if path != '/':
            return False

        return True

    except Exception:
        return False

