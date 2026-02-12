import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry
from urllib.parse import urlparse
import logging
import os
import socket  # For DNS Rebinding protection
import ipaddress  # For IPv6 address range checking
import time  # For TOCTOU mitigation

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_DOMAINS = ["semmle.com", "example.com"]  # Example whitelist - customize this!
ALLOWED_PATHS = {
    "semmle.com": ["/"],  # Allow all paths on semmle.com
    "example.com": ["/api/v1/"]  # Only allow /api/v1/ on example.com
}


def is_valid_url(url):
    """Validates the URL against a whitelist, including domain and path."""
    try:
        result = urlparse(url)
        netloc = result.netloc
        path = result.path

        # Check if the domain is allowed
        if netloc in ALLOWED_DOMAINS:
            # Check if the path is allowed for the domain
            if path.startswith(tuple(ALLOWED_PATHS.get(netloc, []))):
                return result.scheme in ("http", "https")
        elif any(netloc.endswith("." + domain) for domain in ALLOWED_DOMAINS):
            # Handle subdomains
            for domain in ALLOWED_DOMAINS:
                if netloc.endswith("." + domain):
                    # Check if the path is allowed for the base domain
                    if path.startswith(tuple(ALLOWED_PATHS.get(domain, []))):
                        return result.scheme in ("http", "https")
        return False
    except Exception:
        logging.exception("Error parsing URL for validation.")
        return False


def is_public_ip(hostname):
    """
    Checks if the resolved IP address for a hostname is a public IP.
    Protects against DNS rebinding attacks.
    """
    try:
        ip_address_str = socket.gethostbyname(hostname)
        ip_address = ipaddress.ip_address(ip_address_str)

        if ip_address.is_private:
            return False

        # Check for IPv6 private address ranges
        if ip_address.version == 6:
            if ip_address.is_link_local or ip_address.is_site_local:
                return False
            if ip_address.compressed.startswith("fc") or ip_address.compressed.startswith("fe80"):
                return False

        return True
    except socket.gaierror:
        # Handle cases where the hostname cannot be resolved
        logging.warning(f"Could not resolve hostname: {hostname}")
        return False
    except ValueError:
        logging.warning(f"Invalid IP address: {ip_address_str}")
        return False


def make_secure_request(url):
    """
    Makes a secure HTTP request to the specified URL using best practices.

    Args:
        url (str): The URL to request.

    Returns:
        requests.Response: The response object if the request is successful,
                           None otherwise.
    """

    if not is_valid_url(url):
        logging.error(f"Invalid URL: {url}")
        print("Invalid URL provided.")  # Generic user message
        return None

    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            logging.error(f"No hostname found in URL: {url}")
            print("Invalid URL format.")
            return None

        # TOCTOU Mitigation: Resolve IP address immediately before the request
        if not is_public_ip(hostname):
            logging.error(f"Private IP address detected for hostname: {hostname}")
            print("Request blocked due to potential DNS rebinding.")
            return None

        # Configure retry strategy for handling transient errors
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            backoff_factor=1,  # Exponential backoff factor (1 means 1s, 2s, 4s...)
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
            method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "POST"]  # Methods to retry - TRACE REMOVED
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)

        # Create a session object for connection pooling and retries
        http = requests.Session()
        http.mount("https://", adapter)
        http.mount("http://", adapter)  # Consider removing if only HTTPS is desired

        # Set a reasonable timeout to prevent indefinite hanging
        timeout = 10  # seconds

        # Set a custom User-Agent to identify your application
        user_agent = os.environ.get("USER_AGENT", 'MySecureApp/1.0 (Python requests)')  # Configurable User-Agent
        headers = {
            'User-Agent': user_agent
        }

        # Make the request with proper error handling and timeout
        try:
            response = http.get(url, headers=headers, timeout=timeout, verify=True)  # verify=True is crucial for SSL verification

            # Raise HTTPError for bad responses (4xx or 5xx)
            response.raise_for_status()

            return response
        except requests.exceptions.SSLError as e:
            logging.error(f"SSL Error: {e}")
            print("A secure connection could not be established.")
            return None


    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP Error: {e}")  # Log the error
        print("A server error occurred.")  # Generic message for the user
        return None
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection Error: {e}")
        print("A connection error occurred.")
        return None
    except requests.exceptions.Timeout as e:
        logging.error(f"Timeout Error: {e}")
        print("The request timed out.")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Request Exception: {e}")
        print("A request error occurred.")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        print("An unexpected error occurred.")
        return None


# Example usage:
url = "https://semmle.com"
response = make_secure_request(url)

if response:
    print(f"Request to {url} successful. Status code: {response.status_code}")
    # Process the response content (e.g., response.text, response.json())
    # Be mindful of the content type and handle it appropriately.
    # For example, if it's JSON:
    # try:
    #     data = response.json()
    #     print(data)
    # except json.JSONDecodeError:
    #     print("Response is not valid JSON.")
else:
    print(f"Request to {url} failed.")


# --- Certificate Pinning (Example - Advanced) ---
# To implement certificate pinning, you would typically use a library like 'trustme'.
# This example shows the general idea:

# import trustme
#
# def make_secure_request_with_pinning(url, pinned_cert_path):
#     try:
#         # Load the pinned certificate
#         cert_registry = trustme.CertificateRegistry()
#         cert_registry.add_pem_from_file(pinned_cert_path)
#
#         # Make the request using the certificate registry
#         response = requests.get(url, verify=cert_registry.path_to_cert_bundle)
#         response.raise_for_status()
#         return response
#
#     except Exception as e:
#         print(f"Error during request with certificate pinning: {e}")
#         return None

# Example usage of certificate pinning (replace with your actual certificate path):
# pinned_url = "https://example.com"
# pinned_cert_path = "path/to/example.com.pem"  # Replace with the actual path to the certificate
# pinned_response = make_secure_request_with_pinning(pinned_url, pinned_cert_path)
# if pinned_response:
#     print("Request with certificate pinning successful!")
# else:
#     print("Request with certificate pinning failed.")

