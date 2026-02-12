import urllib.parse
import ssl
import requests
import ipaddress
import tldextract
import idna
import logging
import os
import json  # Or YAML, etc.
from urllib.error import URLError  # Import URLError
import validators  # Import a URL validation library

# Load configuration from a JSON file (example)
CONFIG_FILE = "config.json"
try:
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
    ALLOWED_DOMAINS = config.get("allowed_domains", ["example.com"])  # Default if not found
    ALLOWED_IPS = config.get("allowed_ips", ["127.0.0.1"])
    TIMEOUT = config.get("timeout", 10)
    MAX_CONTENT_LENGTH = config.get("max_content_length", 1024 * 1024)
except FileNotFoundError:
    logging.warning(f"Configuration file not found: {CONFIG_FILE}. Using default values.")
    ALLOWED_DOMAINS = ["example.com"]
    ALLOWED_IPS = ["127.0.0.1"]
    TIMEOUT = 10
    MAX_CONTENT_LENGTH = 1024 * 1024
except json.JSONDecodeError as e:
    logging.error(f"Error decoding configuration file: {e}. Using default values.")
    ALLOWED_DOMAINS = ["example.com"]
    ALLOWED_IPS = ["127.0.0.1"]
    TIMEOUT = 10
    MAX_CONTENT_LENGTH = 1024 * 1024

ALLOWED_DOMAINS_LOWER = {d.lower() for d in ALLOWED_DOMAINS}  # Pre-compute lowercase domains

def is_valid_url(url):
    """
    Validates a URL using the validators library.
    """
    return validators.url(url) and url.startswith("https://")  # Requires validators library

# OR, a more manual implementation:
# def is_valid_url(url):
#     """
#     Validates a URL.
#     """
#     try:
#         result = urllib.parse.urlparse(url)
#         if not all([result.scheme == 'https', result.netloc, result.path is not None]):
#             return False
#         # Additional hostname validation (example - more can be added)
#         if not validators.domain(result.netloc):
#             return False
#         return True
#     except:
#         return False

def is_allowed_domain(url, allowed_domains=ALLOWED_DOMAINS_LOWER):
    """
    Checks if the domain of a URL is in the allowlist.

    :param url: The URL to check.
    :param allowed_domains: A list of allowed domains.
    :return: True if the domain is allowed, False otherwise.
    """
    try:
        result = urllib.parse.urlparse(url)
        hostname = result.hostname
        if not hostname:
            return False

        # Handle IDN homograph attacks
        try:
            hostname = idna.encode(hostname).decode('ascii')
        except idna.IDNAError:
            logging.warning(f"IDNAError encoding hostname: {hostname}")
            return False

        # Extract registered domain using tldextract
        extracted = tldextract.extract(hostname)
        registered_domain = ".".join(extracted[1:])  # Combine domain and suffix
        registered_domain_lower = registered_domain.lower()

        for allowed_domain in allowed_domains:
            if registered_domain_lower == allowed_domain or registered_domain_lower.endswith("." + allowed_domain):
                return True
        return False
    except URLError as e:  # Catch specific parsing errors
        logging.error(f"Error parsing URL: {e}")
        return False
    except Exception as e: # Catch any other exceptions and log them
        logging.exception(f"Unexpected error in is_allowed_domain: {e}") # Log the full exception
        return False

