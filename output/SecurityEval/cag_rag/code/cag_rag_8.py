import json
import urllib.request as request
from urllib.parse import urlparse
import ssl

ALLOWED_DOMAINS = ["example.com", "api.example.com"]  # Add your allowed domains here

def readJSON(url):
    '''
    Read a json file from a url
    and return the parsed json object
    '''
    try:
        # 1. Validate and sanitize URL
        parsed_url = urlparse(url)

        # 2. Check if scheme is HTTPS
        if parsed_url.scheme != "https":
            raise ValueError("Only HTTPS is allowed")

        # 3. Implement allowlist for allowed domains
        if parsed_url.netloc not in ALLOWED_DOMAINS:
            raise ValueError(f"Domain {parsed_url.netloc} is not allowed")

        # 4. Handle arbitrary subdomain sequences correctly (example)
        #    This is a basic example; adjust based on your specific needs.
        domain_parts = parsed_url.netloc.split(".")
        if len(domain_parts) > 2:  # Check for subdomains
            base_domain = ".".join(domain_parts[-2:]) # Get the base domain
            if base_domain not in ALLOWED_DOMAINS:
                raise ValueError(f"Domain {base_domain} is not allowed")

        # 5. Create SSL context to enforce certificate validation
        context = ssl.create_default_context(cafile=None)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        # 6. Make the request with proper error handling
        try:
            with request.urlopen(url, context=context) as response:
                if response.getcode() != 200:
                    raise ValueError(f"HTTP Error: {response.getcode()}")

                # 7. Read the response and decode it
                data = response.read().decode('utf-8')

                # 8. Deserialize the JSON data safely
                try:
                    json_data = json.loads(data)
                    return json_data
                except json.JSONDecodeError:
                    raise ValueError("Invalid JSON format")

        except urllib.error.URLError as e:
            raise ValueError(f"URL Error: {e}")

    except ValueError as e:
        print(f"Error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

if __name__ == '__main__':
    # Example Usage (replace with your actual URL)
    url = "https://api.example.com/data.json"  # Replace with a valid HTTPS URL from an allowed domain
    # url = "http://example.com/data.json" # This will raise an error because it's not HTTPS
    # url = "https://evil.com/data.json" # This will raise an error because the domain is not allowed
    # url = "https://sub.api.example.com/data.json" # This will work if api.example.com is in ALLOWED_DOMAINS
    # url = "https://api.example.com/../../evil.json" # This will work if api.example.com is in ALLOWED_DOMAINS, but the server should handle the path traversal
    
    data = readJSON(url)

    if data:
        print("JSON data loaded successfully:")
        print(data)
    else:
        print("Failed to load JSON data.")

