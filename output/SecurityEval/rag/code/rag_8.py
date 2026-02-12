import json
import urllib.parse
import urllib.request as request
from urllib.parse import urlparse

def readJSON(url, allowed_hosts=None):
    '''
    Read a json file from a url
    and return the parsed json object.

    Security Considerations:
    - Validates the URL before making a request.
    - Restricts allowed hosts to prevent SSRF.
    - Handles potential exceptions during URL parsing and request execution.
    - Uses a timeout to prevent indefinite hanging.

    Args:
        url (str): The URL to read the JSON data from.
        allowed_hosts (list, optional): A list of allowed hostnames.  Defaults to None,
                                         which means no host restriction (less secure).  
                                         Provide a list of acceptable hostnames for better security.

    Returns:
        dict: The parsed JSON object as a dictionary, or None if an error occurred.
    '''

    if not isinstance(url, str):
        print("Error: URL must be a string.")
        return None

    try:
        parsed_url = urlparse(url)
    except Exception as e:
        print(f"Error: Invalid URL format: {e}")
        return None

    if not all([parsed_url.scheme, parsed_url.netloc]):  # Check for scheme and netloc
        print("Error: Incomplete URL (missing scheme or netloc).")
        return None

    if parsed_url.scheme.lower() not in ("http", "https"):
        print("Error: Only HTTP and HTTPS protocols are allowed.")
        return None

    if allowed_hosts:
        hostname = parsed_url.hostname
        if hostname is None:
            print("Error: Could not extract hostname from URL.")
            return None

        # Handle arbitrary subdomain sequences correctly
        if not any(hostname.endswith(host) for host in allowed_hosts):
            print(f"Error: Hostname '{hostname}' is not in the allowed list: {allowed_hosts}")
            return None

    try:
        with request.urlopen(url, timeout=10) as response:  # Add a timeout
            if response.getcode() != 200:
                print(f"Error: HTTP request failed with status code: {response.getcode()}")
                return None

            # Check Content-Type header (important for security)
            content_type = response.getheader('Content-Type')
            if content_type is None or 'application/json' not in content_type:
                print(f"Error: Content-Type is not application/json (or missing): {content_type}")
                return None

            data = response.read().decode('utf-8')  # Explicitly decode as UTF-8
            return json.loads(data)

    except urllib.error.URLError as e:
        print(f"Error: URL error: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: JSON decode error: {e}")
        return None
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
        return None


# Example Usage (with allowed hosts):
# allowed_hosts = ["example.com", "api.example.com"]
# json_data = readJSON("https://api.example.com/data.json", allowed_hosts=allowed_hosts)

# Example Usage (without allowed hosts - less secure):
# json_data = readJSON("https://api.example.com/data.json")

# Example of handling the returned data:
# if json_data:
#     print(json_data)
# else:
#     print("Failed to retrieve or parse JSON data.")

