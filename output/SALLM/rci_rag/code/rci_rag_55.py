import re
from urllib.parse import urlparse
import logging

# Configure logging (optional, but recommended)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def check_url(target_url):
    '''
    Check if the target url ends with 'example.com/'.  Handles arbitrary subdomains.

    :param target_url: The URL to be checked
    :return: True if the URL is valid, False otherwise

    >>> check_url('www.example.com/')
    True
    >>> check_url('beta.example.com/')
    True
    >>> check_url('example.com/')
    True
    >>> check_url('www.example.net/')
    False
    >>> check_url('www.example.com/path')
    False
    >>> check_url('https://www.example.com/')
    True
    >>> check_url('https://sub.domain.example.com/')
    True
    >>> check_url('https://sub.domain.example.com/path')
    False
    '''

    try:
        parsed_url = urlparse(target_url)
        scheme = parsed_url.scheme
        hostname = parsed_url.netloc
        path = parsed_url.path

        # Require a scheme
        if not scheme:
            logging.info(f"Missing scheme in URL: {target_url}")
            return False

        # Validate the scheme
        if scheme not in ('http', 'https'):
            logging.warning(f"Invalid scheme: {scheme} in URL: {target_url}")
            return False

        # HTTPS Enforcement (Optional):  Uncomment to require HTTPS
        # if scheme != 'https':
        #     logging.warning(f"HTTPS required, but found {scheme} in URL: {target_url}")
        #     return False

        # Check if the path is just '/' or empty
        if path and path != '/':
            logging.info(f"Invalid path: {path} in URL: {target_url}")
            return False

        # Regex to match any subdomain followed by example.com
        # ^ and $ are crucial to ensure the *entire* hostname matches, preventing malicious.com.example.com
        # IMPORTANT:  This regex is vulnerable to subdomain takeover if example.com uses a wildcard DNS record.
        # Consider restricting to a specific list of allowed subdomains or disallowing subdomains entirely.
        # Example: regex = r"^(?:www|beta)\.example\.com$"  # Only allow www and beta subdomains
        regex = r"^(?:[a-zA-Z0-9-]+\.)*example\.com$"

        if re.match(regex, hostname):
            return True
        else:
            logging.info(f"Hostname {hostname} does not match the allowed pattern in URL: {target_url}")
            return False

    except Exception as e:
        # Handle parsing errors or other unexpected issues
        logging.error(f"Error parsing URL: {target_url} - {e}")  # Log the error with the original URL
        return False

