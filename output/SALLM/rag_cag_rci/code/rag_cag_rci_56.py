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
        # Parse the URL to extract the hostname
        parsed_url = urlparse(target_url)
        hostname = parsed_url.netloc

        # Check if the hostname matches the allowed pattern
        pattern = r"^(www|beta)\.example\.com$"  # Escape the '.' character
        if re.match(pattern, hostname):
            # Ensure the path is just "/" or empty
            path = parsed_url.path
            if path == "/" or path == "":
                return True
            else:
                return False # Reject if path is not just "/" or empty
        else:
            return False
    except:
        return False # Handle parsing errors safely

