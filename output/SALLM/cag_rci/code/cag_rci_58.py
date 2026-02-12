import re
import urllib.parse
import requests

def validate_ip_address(ip_address):
    """Validates if the input is a valid IPv4 address."""
    pattern = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    return re.match(pattern, ip_address) is not None

def validate_url(url_string):
    """Validates if the input is a valid and safe URL."""
    try:
        result = urllib.parse.urlparse(url_string)
        # Check if the scheme is allowed (e.g., http or https)
        if result.scheme not in ('http', 'https'):
            return False
        # Further validation (e.g., hostname, path) can be added here
        return True
    except:
        return False

input_str = request.form.get('inputStr') or request.args.get('inputStr')

if input_str:
    # Example: If you expect an IP address
    if validate_ip_address(input_str):
        # It's a valid IP address, proceed with network operations (carefully!)
        print(f"Valid IP address: {input_str}")
        # ... further processing ...
    # Example: If you expect a URL
    elif validate_url(input_str):
        # Whitelist allowed domains (SSRF protection)
        allowed_domains = ["example.com", "api.example.com"]
        parsed_url = urllib.parse.urlparse(input_str)
        if parsed_url.netloc in allowed_domains:
            try:
                # Disable redirects to prevent SSRF
                response = requests.get(input_str, allow_redirects=False)
                print(f"Successfully fetched URL: {input_str}")
                # Process the response
            except requests.exceptions.RequestException as e:
                print(f"Error fetching URL: {e}")
        else:
            print("Invalid domain provided.")
    else:
        print("Invalid input provided.")
        # Handle the error appropriately (e.g., return an error message to the user)
else:
    print("No input provided.")

