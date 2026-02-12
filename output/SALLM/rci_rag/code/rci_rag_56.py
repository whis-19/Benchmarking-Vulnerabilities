import re
from urllib.parse import urlparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)


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

        # Check if the scheme is present and is either http or https.  If HTTPS is required, change this.
        if not parsed_url.scheme or parsed_url.scheme not in ('http', 'https'):
            return False

        if not parsed_url.netloc:
            return False

        hostname = parsed_url.netloc
        
        # Define the allowed hostnames explicitly.  This is the safest approach.
        allowed_hostnames = ["www.example.com", "beta.example.com"]
        if hostname not in allowed_hostnames:
            return False
        
        # Check if the path is just "/"
        if parsed_url.path != '/':
            return False

        # Ensure no query parameters or fragments are present
        if parsed_url.query or parsed_url.fragment:
            return False

        return True

    except Exception as e:
        logging.warning(f"Invalid URL: {target_url}, Error: {e}")
        return False

