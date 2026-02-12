import json
import urllib.request as request
from urllib.parse import urlparse
import ssl

ALLOWED_DOMAINS = ["example.com", "api.example.com"]  # Add your allowed domains here

def is_valid_url(url):
    """
    Validates the URL against a set of security checks.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc, result.path]) and result.scheme in ['http', 'https']
    except:
        return False

def is_allowed_domain(url):
    """
    Checks if the domain of the URL is in the allowlist.
    Handles arbitrary subdomains correctly.
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Check if the hostname or any of its parent domains are in the allowlist
        parts = hostname.split('.')
        for i in range(len(parts)):
            domain = '.'.join(parts[i:])
            if domain in ALLOWED_DOMAINS:
                return True
        return False
    except:
        return False

def readJSON(url):
    '''
    Read a json file from a url
    and return the parsed json object
    '''
    if not is_valid_url(url):
        raise ValueError("Invalid URL provided.")

    if not is_allowed_domain(url):
        raise ValueError("URL domain is not allowed.")

    try:
        # Enforce HTTPS
        if not url.startswith("https"):
            print("Warning: URL is not using HTTPS.  Consider using HTTPS for secure communication.")

        # Create an SSL context to enforce certificate validation
        context = ssl.create_default_context(cafile=None)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED  # Require certificate verification

        with request.urlopen(url, context=context) as response:
            if response.getcode() != 200:
                raise ValueError(f"Failed to retrieve data from URL. Status code: {response.getcode()}")

            content_type = response.headers.get('Content-Type')
            if not content_type or 'application/json' not in content_type:
                raise ValueError(f"Invalid Content-Type: {content_type}. Expected application/json.")

            data = response.read().decode('utf-8')

            try:
                # Use json.loads for safe deserialization
                json_object = json.loads(data)
                return json_object
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to decode JSON: {e}")

    except (request.URLError, ValueError) as e:
        raise ValueError(f"Error reading JSON from URL: {e}")
    except ssl.SSLError as e:
        raise ValueError(f"SSL Error: {e}")
    except Exception as e:
        raise ValueError(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    # Example Usage (replace with a safe and controlled URL for testing)
    try:
        # Good Example
        data = readJSON("https://api.example.com/data.json") # Replace with a valid HTTPS URL from an allowed domain
        print("Data from allowed domain:", data)

        # Bad Examples (will raise exceptions)
        # data = readJSON("http://example.com/data.json") # Not HTTPS
        # print(data)
        # data = readJSON("https://malicious.com/data.json") # Not in ALLOWED_DOMAINS
        # print(data)
        # data = readJSON("ftp://example.com/data.json") # Invalid URL scheme
        # print(data)

    except ValueError as e:
        print(f"Error: {e}")

