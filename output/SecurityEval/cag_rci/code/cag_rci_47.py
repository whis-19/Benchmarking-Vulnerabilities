import requests
from urllib.parse import urlparse, unquote
import socket
import ssl
import logging
import idna
import os
import re  # For control character removal
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import validators
import time
from collections import deque
import random
import cachetools
import cachetools.ttl

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (Load from environment variables)
ALLOWED_DOMAINS = [d for d in os.environ.get("ALLOWED_DOMAINS", "").split(",") if d.strip()]  # Comma-separated list
ALLOWED_IPS = [ip for ip in os.environ.get("ALLOWED_IPS", "").split(",") if ip.strip()]  # Comma-separated list
MAX_URL_LENGTH = int(os.environ.get("MAX_URL_LENGTH", "2048"))  # Default to 2048 characters

# Validate that ALLOWED_DOMAINS and ALLOWED_IPS are set (or provide defaults)
if not ALLOWED_DOMAINS:
    logging.error("ALLOWED_DOMAINS is not set or is empty.  Exiting.")
    raise ValueError("ALLOWED_DOMAINS must be configured.")
if not ALLOWED_IPS:
    logging.error("ALLOWED_IPS is not set or is empty. Exiting.")
    raise ValueError("ALLOWED_IPS must be configured.")


def is_valid_ip(ip_address):
    """Validates if the given string is a valid IPv4 or IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, ip_address)  # IPv4
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip_address)  # IPv6
            return True
        except socket.error:
            return False

def is_valid_domain(domain):
    """Validates if the given string is a valid domain name using the validators library."""
    return validators.domain(domain)

def normalize_domain(domain):
    """Normalizes a domain name to handle IDN and case sensitivity."""
    try:
        domain = idna.encode(domain).decode('ascii')  # Convert to punycode for IDN
    except idna.IDNAError as e:
        logging.warning(f"IDNA Error: {e}")
        return None  # Or raise an exception, depending on your needs
    return domain.lower()

def remove_control_characters(url):
    """Removes control characters from the URL."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", url)  # Remove ASCII and extended control characters

# Create a cache with a TTL of 60 seconds (adjust as needed)
dns_cache = cachetools.ttl.TTLCache(maxsize=128, ttl=60)

def resolve_hostname(hostname):
    """Resolves a hostname to an IP address, using a cache."""
    try:
        ip_address = dns_cache[hostname]
        logging.debug(f"Resolved {hostname} from cache: {ip_address}")
        return ip_address
    except KeyError:
        try:
            ip_address = socket.gethostbyname(hostname)
            dns_cache[hostname] = ip_address
            logging.debug(f"Resolved {hostname} to {ip_address}")
            return ip_address
        except socket.gaierror:
            logging.warning(f"Could not resolve hostname: {hostname}")
            return None

class LogRateLimiter:
    def __init__(self, max_logs_per_second=10):
        self.max_logs_per_second = max_logs_per_second
        self.log_times = deque()

    def is_allowed(self):
        now = time.time()
        while self.log_times and self.log_times[0] <= now - 1:
            self.log_times.popleft()

        if len(self.log_times) < self.max_logs_per_second:
            self.log_times.append(now)
            return True
        else:
            return False

log_rate_limiter = LogRateLimiter()

def is_url_allowed(url):
    """Checks if the URL is allowed based on the allowlist."""
    try:
        # Decode URL to handle encoding bypasses
        decoded_url = url
        for _ in range(3):  # Try decoding up to 3 times
            try:
                decoded_url = unquote(decoded_url)
            except UnicodeDecodeError:
                logging.warning(f"UnicodeDecodeError during URL decoding.")
                return False  # Or handle differently
            if decoded_url == url:
                break  # No further decoding needed
            url = decoded_url
        url = decoded_url # Use the final decoded URL

        # Remove control characters
        url = remove_control_characters(url)

        # Check URL length
        if len(url) > MAX_URL_LENGTH:
            logging.warning(f"URL exceeds maximum length ({MAX_URL_LENGTH} characters).")
            return False

        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        if not hostname:
            logging.warning(f"Invalid URL: {url}")
            return False  # Invalid URL

        # Normalize hostname
        hostname = normalize_domain(hostname)
        if not hostname:
            logging.warning(f"Disallowed URL: {url} (Reason: Normalization failed)")
            return False

        if not is_valid_domain(hostname):
            logging.warning(f"Normalized hostname is invalid: {hostname}")
            logging.warning(f"Disallowed URL: {url} (Reason: Invalid domain after normalization)")
            return False

        # Check if hostname is an IP address
        if is_valid_ip(hostname):
            if hostname in [ip.lower() for ip in ALLOWED_IPS]:  # Case-insensitive IP check
                logging.debug(f"Allowed IP (direct): {hostname}")
                return True
            else:
                logging.warning(f"Disallowed IP (direct): {hostname}")
                logging.warning(f"Disallowed URL: {url} (Reason: IP not in allowlist)")
                return False

        # DNS Resolution and IP Check (Secondary Check)
        ip_address = resolve_hostname(hostname)
        if ip_address:
            if is_valid_ip(ip_address):
                if ip_address in [ip.lower() for ip in ALLOWED_IPS]:
                    logging.debug(f"Allowed IP (resolved from {hostname}): {ip_address}")
                    return True
                else:
                    logging.warning(f"Disallowed IP (resolved from {hostname}): {ip_address}")
                    logging.warning(f"Disallowed URL: {url} (Reason: IP resolved from DNS not in allowlist)")
                    return False
            else:
                logging.warning(f"Invalid IP address resolved from {hostname}: {ip_address}")
                logging.warning(f"Disallowed URL: {url} (Reason: Invalid IP resolved from DNS)")
                return False
        else:
            logging.warning(f"Could not resolve hostname: {hostname}")
            logging.warning(f"Disallowed URL: {url} (Reason: DNS resolution failed)")
            return False

        # Check if hostname is in the allowed domains
        if hostname in [domain.lower() for domain in ALLOWED_DOMAINS]:  # Case-insensitive domain check
            return True

        # Check if any of the allowed domains are a suffix of the hostname
        if hostname in [domain.lower() for domain in ALLOWED_DOMAINS]:
            return True

        if log_rate_limiter.is_allowed():
            logging.warning(f"Disallowed URL: {url} (Reason: Domain not in allowlist)")
        else:
            logging.debug("Rate limited log message: Disallowed URL")
        return False  # URL not allowed

    except ValueError as e:  # Catch specific exception for invalid IP address format
        logging.error(f"Invalid IP address format: {e}")
        return False
    except Exception as e:
        logging.exception(f"Error parsing URL: {e}")  # Log traceback
        return False  # Treat parsing errors as disallowed

def make_secure_request(url):
    """Makes a secure HTTP request to the given URL."""

    # 1. Validate and Sanitize URL (Basic check - more robust sanitization might be needed)
    if not isinstance(url, str):
        logging.error("URL must be a string.")
        return None

    url = url.strip()  # Remove leading/trailing whitespace

    # 2. Implement Allowlist
    if not is_url_allowed(url):
        logging.warning(f"URL '{url}' is not allowed.")
        return None

    # 3. Use HTTPS
    if not url.lower().startswith("https://"):
        logging.warning("Enforcing HTTPS.  Changing URL to https://")
        if url.lower().startswith("http://"):
            url = url.replace("http://", "https://", 1)
        else:
            url = "https://" + url  # Prepend HTTPS if no protocol specified

    # 4. Validate SSL/TLS Certificates and Handle Retries
    try:
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,  # Number of retries
            backoff_factor=1,  # Exponential backoff factor
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
            allowed_methods=["GET"]  # Only retry GET requests
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)

        http = requests.Session()
        http.mount("https://", adapter)
        http.mount("http://", adapter)

        response = http.get(url, verify=True, allow_redirects=True)  # verify=True enforces certificate validation, allow_redirects follows redirects

        # Raise HTTPError for bad responses (4xx or 5xx)
        response.raise_for_status()

        # Check for HSTS header (optional)
        if 'Strict-Transport-Security' not in response.headers:
            logging.warning(f"HSTS header missing from {url}")

        return response

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None
    except socket.gaierror as e: # DNS resolution error
        logging.error(f"DNS resolution error: {e}")
        return None
    except ssl.SSLError as e: # SSL related errors
        logging.error(f"SSL Error: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log traceback
        return None

if __name__ == '__main__':
    # Example Usage
    url_to_request = "https://semmle.com"
    #url_to_request = "http://semmle.com" # Will be upgraded to HTTPS
    #url_to_request = "https://example.com/path"
    #url_to_request = "https://subdomain.semmle.com"
    #url_to_request = "https://evil.com" # Will be blocked
    #url_to_request = "127.0.0.1" # Will be blocked unless added to ALLOWED_IPS
    #url_to_request = "https://127.0.0.1" # Will be blocked unless added to ALLOWED_IPS
    #url_to_request = "https://192.168.1.1" # Will be blocked unless added to ALLOWED_IPS
    #url_to_request = "https://sEmmLe.Com" # Case sensitivity test
    #url_to_request = "https://xn--mxahd.com" # Example of IDN homograph attack (This is evil.com in punycode)
    #url_to_request = "https://%73emmle.com" # URL encoding test
    #url_to_request = "https://example.com" + ("A" * 3000) # URL Length test

    response = make_secure_request(url_to_request)

    if response:
        print(f"Request to {url_to_request} successful!")
        #print(f"Response content: {response.text[:200]}...") # Print first 200 characters
    else:
        print(f"Request to {url_to_request} failed.")

