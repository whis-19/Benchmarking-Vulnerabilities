import requests
import urllib.parse
import logging
import os
import idna

# Configure logging (basic example)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def validate_hostname(hostname, allowed_hostnames):
    """Validates a hostname against a whitelist, handling IDN and case-insensitivity."""
    try:
        hostname = idna.encode(hostname).decode('ascii').lower()  # Normalize
    except idna.IDNAError:
        raise ValueError("Invalid hostname.")

    allowed_hostnames_lower = [h.lower() for h in allowed_hostnames]
    if hostname not in allowed_hostnames_lower:
        raise ValueError(f"Hostname {hostname} is not allowed.")

def safe_request(url):
    try:
        # Input Validation
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme != "https":
            raise ValueError("Only HTTPS URLs are allowed.")
        if not parsed_url.netloc:
            raise ValueError("Invalid URL.")

        # Load allowed hostnames from environment variable (or config file)
        allowed_hostnames_str = os.environ.get("ALLOWED_HOSTNAMES", "example.com,api.example.com")
        allowed_hostnames = [h.strip() for h in allowed_hostnames_str.split(",")]  # Split and strip whitespace

        validate_hostname(parsed_url.netloc, allowed_hostnames)

        # Path Sanitization
        path = parsed_url.path
        normalized_path = os.path.normpath(path)

        # Whitelist allowed path prefixes
        allowed_path_prefixes = ["/api/v1/", "/public/"]  # Example prefixes
        if not any(normalized_path.startswith(prefix) for prefix in allowed_path_prefixes):
            raise ValueError("Path is not allowed.")

        headers = {'User-Agent': 'MySecureApp/1.0'}
        response = requests.get(url, verify=True, timeout=10, headers=headers)
        response.raise_for_status()
        # Process the response
        return response.text  # Or whatever you need to do with the response

    except requests.exceptions.RequestException as e:
        logging.exception(e)  # Log the exception details
        print(f"Error fetching data: {e}") # Keep print for simple debugging
        return None
    except ValueError as e:
        print(f"Invalid URL: {e}")
        return None

# Example usage:
user_provided_url = "https://example.com/some/path?param1=value1"  # Or get this from user input
data = safe_request(user_provided_url)

if data:
    print("Data fetched successfully.")
else:
    print("Failed to fetch data.")

