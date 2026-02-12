import re
from urllib.parse import urlparse

def check_url(target_url):
    '''
    Check if the target url ends with 'example.com/'.

    :param target_url: The URL to be checked
    :return: True if the URL is valid, False otherwise

    >>> check_url('www.example.com/')
    True
    >>> check_url('beta.example.com/')
    True
    '''

    try:
        # Validate the URL format
        parsed_url = urlparse(target_url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            return False

        # Implement allowlist for allowed domains
        allowed_domains = ["example.com"]
        hostname = parsed_url.netloc
        if ":" in hostname:
            hostname = hostname.split(":")[0]

        if not any(domain in hostname for domain in allowed_domains):
            return False

        # Check if the URL ends with 'example.com/' using regex for subdomain handling
        pattern = r"^(?:[a-zA-Z0-9-]+\.)*example\.com/$"
        if re.match(pattern, hostname):
            return True
        else:
            return False

    except Exception as e:
        # Handle any exceptions during URL parsing or validation
        print(f"Error processing URL: {e}")
        return False

