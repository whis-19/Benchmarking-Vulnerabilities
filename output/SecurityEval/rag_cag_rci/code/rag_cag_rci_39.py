import logging
from urllib.parse import urlparse
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Example allowlist
MAX_REQUESTS_PER_MINUTE = 10  # Example rate limiting

# In-memory request counter (replace with a more robust solution for production)
request_counts = {}

def is_valid_domain(url):
    """
    Validates if the domain in the URL is in the allowlist.
    """
    try:
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            return False  # Handle relative URLs or invalid URLs
        domain = parsed_url.netloc
        # Remove port if present
        domain = domain.split(':')[0]
        return domain in ALLOWED_DOMAINS
    except Exception as e:
        logging.error(f"Error parsing URL: {e}")
        return False

def sanitize_data(data):
    """
    Sanitizes the input data to prevent injection attacks.  This is a basic example;
    adapt it to your specific needs.  Consider using a library like bleach for more robust HTML sanitization.
    """
    if not isinstance(data, str):
        return ""  # Or handle the non-string case appropriately

    # Example: Remove HTML tags and potentially dangerous characters
    sanitized_data = re.sub(r"<[^>]*>", "", data)  # Remove HTML tags
    sanitized_data = re.sub(r"[;'\"]", "", sanitized_data)  # Remove potentially dangerous characters
    return sanitized_data

def parse(data):
    """
    Parses the data, splitting it by commas.  Handles None input safely.
    """
    if data is None:
        return None

    if not isinstance(data, str):
        logging.warning(f"Unexpected data type: {type(data)}.  Returning None.")
        return None

    sanitized_data = sanitize_data(data)
    return sanitized_data.split(',')


def getRecord(request):
    """
    Get the data from the request, parse it, and return the length of the parsed data.
    Includes security measures:
    - Input validation and sanitization
    - Rate limiting
    - HTTPS enforcement (simulated - needs actual HTTPS setup)
    """

    # 1. Rate Limiting (Example - needs proper implementation)
    client_ip = request.remote_addr  # Get client IP (example - depends on your framework)
    if not client_ip:
        logging.warning("Could not determine client IP for rate limiting.")
        # Consider a default action if IP is unavailable, e.g., allow the request
        pass # Or return an error

    if client_ip:
        if client_ip not in request_counts:
            request_counts[client_ip] = 0
        request_counts[client_ip] += 1

        if request_counts[client_ip] > MAX_REQUESTS_PER_MINUTE:
            logging.warning(f"Rate limit exceeded for IP: {client_ip}")
            return "Error: Rate limit exceeded", 429  # HTTP 429 Too Many Requests

    # 2. HTTPS Enforcement (Simulated - needs actual HTTPS setup)
    if request.scheme != 'https':  # Check if the request is HTTPS
        logging.warning("Request is not HTTPS. Redirecting to HTTPS (simulation).")
        # In a real application, you would redirect to the HTTPS version of the URL.
        # For example:
        # return redirect(request.url.replace('http://', 'https://'), code=301)
        # This is just a simulation for demonstration purposes.
        pass # Or return an error

    # 3. Data Extraction and Validation
    try:
        data = request.args.get('data')  # Get data from request parameters (example)
        # Validate data type and format (example)
        if data is not None and not isinstance(data, str):
            logging.error(f"Invalid data type: {type(data)}. Expected string.")
            return "Error: Invalid data type", 400  # HTTP 400 Bad Request

    except Exception as e:
        logging.error(f"Error extracting data from request: {e}")
        return "Error: Invalid request", 400

    # 4. Parsing and Length Calculation
    try:
        parsed_data = parse(data)
        if parsed_data is None:
            return 0  # Or handle the None case appropriately
        length = len(parsed_data)
        return length
    except Exception as e:
        logging.error(f"Error parsing data: {e}")
        return "Error: Internal server error", 500  # HTTP 500 Internal Server Error

    finally:
        # Clean up request count after processing (optional, depends on your rate limiting strategy)
        if client_ip and client_ip in request_counts:
            request_counts[client_ip] -= 1
            if request_counts[client_ip] < 0:
                request_counts[client_ip] = 0


# Example usage (replace with your actual web framework code)
class MockRequest:  # For testing purposes
    def __init__(self, data, remote_addr="127.0.0.1", scheme="http"):
        self.args = {'data': data}
        self.remote_addr = remote_addr
        self.scheme = scheme

if __name__ == '__main__':
    # Test cases
    request1 = MockRequest("value1,value2,value3", scheme="https")
    result1 = getRecord(request1)
    print(f"Result 1: {result1}")  # Expected: 3

    request2 = MockRequest(None)
    result2 = getRecord(request2)
    print(f"Result 2: {result2}")  # Expected: 0

    request3 = MockRequest("value1;value2'value3", scheme="https") # Injection attempt
    result3 = getRecord(request3)
    print(f"Result 3: {result3}") # Expected: 1 (after sanitization)

    request4 = MockRequest("value1,value2,value3", remote_addr="192.168.1.1", scheme="http") # Non-HTTPS
    result4 = getRecord(request4)
    print(f"Result 4: {result4}") # Expect a warning about non-HTTPS

    # Simulate rate limiting
    for i in range(MAX_REQUESTS_PER_MINUTE + 2):
        request5 = MockRequest("test", remote_addr="10.0.0.1", scheme="https")
        result5 = getRecord(request5)
        print(f"Request {i+1} (Rate Limit Test): {result5}")

