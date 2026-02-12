import urllib.parse
import requests
from requests.exceptions import RequestException
import ssl
import ipaddress
import logging
import socket
import html  # For HTML escaping
import os  # For environment variables
import json # For JSON configuration
import re # For regular expressions
import shlex # For shell command escaping

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration from JSON file first, then override with environment variables
ALLOWED_DOMAINS = []
ALLOWED_IPS = []

try:
    with open("config.json", "r") as f:
        config = json.load(f)
        ALLOWED_DOMAINS = config.get("ALLOWED_DOMAINS", [])
        ALLOWED_IPS = config.get("ALLOWED_IPS", [])
except FileNotFoundError:
    logging.warning("config.json not found, using default ALLOWED_DOMAINS and ALLOWED_IPS")
    ALLOWED_DOMAINS = ["localhost"]  # Secure default
    ALLOWED_IPS = ["127.0.0.1"]  # Secure default
except json.JSONDecodeError:
    logging.error("Invalid JSON in config.json, using default ALLOWED_DOMAINS and ALLOWED_IPS")
    ALLOWED_DOMAINS = ["localhost"]  # Secure default
    ALLOWED_IPS = ["127.0.0.1"]  # Secure default
except Exception as e:
    logging.exception(f"Error loading config.json: {e}")
    ALLOWED_DOMAINS = ["localhost"]  # Secure default
    ALLOWED_IPS = ["127.0.0.1"]  # Secure default

# Override with environment variables (optional, but be careful!)
if os.environ.get("ALLOWED_DOMAINS"):
    try:
        ALLOWED_DOMAINS = json.loads(os.environ.get("ALLOWED_DOMAINS"))
    except json.JSONDecodeError:
        logging.error("Invalid JSON in ALLOWED_DOMAINS environment variable, using config.json or default")

if os.environ.get("ALLOWED_IPS"):
    try:
        ALLOWED_IPS = json.loads(os.environ.get("ALLOWED_IPS"))
    except json.JSONDecodeError:
        logging.error("Invalid JSON in ALLOWED_IPS environment variable, using config.json or default")

# Validate ALLOWED_DOMAINS and ALLOWED_IPS
def validate_domain(domain):
    """Validates a domain name using a regular expression."""
    domain_regex = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    )
    return bool(domain_regex.match(domain))

def validate_ip(ip):
    """Validates an IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

validated_domains = []
for domain in ALLOWED_DOMAINS:
    if isinstance(domain, str) and validate_domain(domain):
        validated_domains.append(domain)
    else:
        logging.error(f"Invalid domain in ALLOWED_DOMAINS: {domain}")
        raise ValueError(f"Invalid domain in ALLOWED_DOMAINS: {domain}") # Fail fast

ALLOWED_DOMAINS = validated_domains

validated_ips = []
for ip in ALLOWED_IPS:
    if isinstance(ip, str) and validate_ip(ip):
        validated_ips.append(ip)
    else:
        logging.error(f"Invalid IP in ALLOWED_IPS: {ip}")
        raise ValueError(f"Invalid IP in ALLOWED_IPS: {ip}") # Fail fast
ALLOWED_IPS = validated_ips

logging.info(f"ALLOWED_DOMAINS: {ALLOWED_DOMAINS}")
logging.info(f"ALLOWED_IPS: {ALLOWED_IPS}")

def is_valid_domain(url):
    """
    Checks if the domain of the URL is in the allowlist, handling IDNA.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            return False

        normalized_hostname = normalize_domain(hostname)
        if not normalized_hostname:
            return False

        if normalized_hostname in ALLOWED_DOMAINS:
            return True

        # Check if hostname is an IP address
        try:
            ip_address = ipaddress.ip_address(hostname)
            if str(ip_address) in ALLOWED_IPS:
                return True
        except ValueError:
            pass  # Not a valid IP address
        return False
    except Exception as e:
        logging.error(f"Error validating domain: {e}")
        return False  # Invalid URL format

def parse(data, context="html"):
    """
    Parses the input data by splitting it on commas and sanitizes based on the context.
    Handles None input gracefully and limits the number of splits.
    """
    if data is None:
        return None
    # Limit the number of splits to prevent DoS
    max_splits = 1000
    split_data = data.split(',', max_splits)

    if context == "html":
        sanitized_data = [html.escape(item) for item in split_data]
    elif context == "database":
        #  In a real application, you would *never* directly insert data into a query string.
        #  Instead, use parameterized queries.  This is just an example.
        sanitized_data = split_data # Placeholder - use parameterized queries!
    elif context == "shell":
        sanitized_data = [shlex.quote(item) for item in split_data]
    else:
        sanitized_data = split_data # No sanitization

    return sanitized_data

def getRecord(request):
    """
    Get the data from the request, parse it, and return the length of the parsed data.
    Implements security measures:
    - URL validation and sanitization
    - Domain/IP allowlisting
    - HTTPS enforcement
    - SSL/TLS certificate validation
    """
    try:
        url = request  # Assuming 'request' is the URL string

        # Validate URL scheme (HTTPS only)
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme.lower() != "https":
            raise ValueError("Only HTTPS requests are allowed.")

        # Validate domain/IP against allowlist
        if not is_valid_domain(url):
            raise ValueError("Domain/IP not allowed.")

        # Sanitize the URL (optional, but good practice)
        sanitized_url = urllib.parse.quote(url, safe=':/')  # Quote special characters

        # Configure SSL/TLS certificate verification and timeout
        try:
            headers = {
                'User-Agent': 'MyApplication/1.0',  # Replace with your application's name and version
                'X-Frame-Options': 'DENY', # Prevent clickjacking
                'X-Content-Type-Options': 'nosniff', # Prevent MIME sniffing
                'Content-Security-Policy': "default-src 'self'", # Example CSP
                # Add other headers as needed (e.g., Content-Type, X-Frame-Options)
            }
            response = requests.get(sanitized_url, verify=True, timeout=10, headers=headers)  # Enforce certificate validation and set timeout
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.text  # Get the response content
        except RequestException as e:
            logging.error(f"Request failed for {sanitized_url}: {e}")
            return None  # Or raise the exception if appropriate

        # Parse the data (example: sanitizing for HTML output)
        parsed_data = parse(data, context="html")

        # Return the length of the parsed data
        if parsed_data is not None:
            return len(parsed_data)
        else:
            return 0  # Or None, depending on desired behavior

    except ValueError as e:
        logging.warning(f"Invalid URL or data: {e}")  # Log the error
        return None  # Or raise the exception if appropriate
    except RequestException as e:
        logging.error(f"Network error: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred for {url}: {e}")  # Log the error with traceback
        return None  # Or raise the exception if appropriate

# Example usage (replace with your actual request)
if __name__ == '__main__':
    # Example 1: Allowed domain
    url1 = "https://example.com/data"
    length1 = getRecord(url1)
    print(f"Length for {url1}: {length1}")

    # Example 2: Allowed IP
    url2 = "https://127.0.0.1/data"
    length2 = getRecord(url2)
    print(f"Length for {url2}: {length2}")

    # Example 3: Disallowed domain
    url3 = "https://bad-example.com/data"
    length3 = getRecord(url3)
    print(f"Length for {url3}: {length3}")  # Will likely print None due to the ValueError

    # Example 4: Non-HTTPS URL
    url4 = "http://example.com/data"
    length4 = getRecord(url4)
    print(f"Length for {url4}: {length4}")  # Will likely print None due to the ValueError

    # Example 5: URL with data
    url5 = "https://example.com/data?param1=value1,value2,value3"
    length5 = getRecord(url5)
    print(f"Length for {url5}: {length5}")

    # Example 6: Unicode Homograph Attack
    url6 = "https://exаmple.com/data"  # Cyrillic 'а'
    length6 = getRecord(url6)
    print(f"Length for {url6}: {length6}")

    # Example 7: Unicode Homograph Attack 2
    url7 = "https://аррӏе.com" # Cyrillic a, Greek i, Cyrillic е
    length7 = getRecord(url7)
    print(f"Length for {url7}: {length7}")

    # Example 8: Shell command injection (demonstrates sanitization)
    data_to_parse = "value1; rm -rf /" # VERY DANGEROUS
    parsed_data_shell = parse(data_to_parse, context="shell")
    print(f"Sanitized for shell: {parsed_data_shell}") # Shows how shlex.quote escapes the data

