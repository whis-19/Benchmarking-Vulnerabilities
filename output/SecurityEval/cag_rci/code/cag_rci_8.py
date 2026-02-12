import json
import urllib.request as request
from urllib.parse import urlparse
import ssl
import hashlib
import hmac
import os
import jsonschema
import tempfile
import logging  # Import the logging library
import sys

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration - Security Parameters
ALLOWED_DOMAINS = ["example.com", "api.example.org"]  # Whitelist of allowed domains

# Load HMAC_SECRET from environment variable (or a more secure location)
HMAC_SECRET = os.environ.get("HMAC_SECRET")
if not HMAC_SECRET:
    logging.critical("HMAC_SECRET environment variable not set. Exiting.")  # Log a critical error
    sys.exit(1)  # Exit the program if the secret is not set
HMAC_SECRET = HMAC_SECRET.encode('utf-8')  # Ensure it's bytes

# JSON Schema for validation
JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "message": {"type": "string"},
        "value": {"type": "integer"}
    },
    "required": ["message", "value"]
}

# Maximum allowed JSON payload size (in bytes)
MAX_JSON_SIZE = 1024 * 1024  # 1MB - Adjust as needed


def is_valid_url(url):
    """
    Validates that the URL is well-formed and uses HTTPS.
    """
    try:
        result = urlparse(url)
        return all([result.scheme == "https", result.netloc, result.path])
    except:
        return False


def is_allowed_domain(url):
    """
    Checks if the domain of the URL is in the allowlist.
    """
    try:
        domain = urlparse(url).netloc
        return domain in ALLOWED_DOMAINS
    except:
        return False


def validate_url(url):
    """
    Validates the URL against security requirements.  Raises ValueError if invalid.
    """
    if not is_valid_url(url):
        logging.warning(f"Invalid URL: {url} - Must be a valid HTTPS URL.")  # Log the warning
        raise ValueError("Invalid URL: Must be a valid HTTPS URL.")
    if not is_allowed_domain(url):
        logging.warning(f"Invalid URL: {url} - Domain not in allowlist ({ALLOWED_DOMAINS}).")  # Log the warning
        raise ValueError(f"Invalid URL: Domain not in allowlist ({ALLOWED_DOMAINS}).")


def calculate_hmac(data, secret):
    """
    Calculates the HMAC-SHA256 hash of the data using the provided secret key.
    """
    return hmac.new(secret, data, hashlib.sha256).hexdigest()


def readJSON(url, expected_hash=None):  # Pass expected_hash as an argument
    """
    Reads a JSON file from a URL, performing security checks.
    """

    validate_url(url)

    try:
        # Create an SSL context to enforce certificate validation
        context = ssl.create_default_context(cafile=None)  # Use system's default CA store
        context.check_hostname = True  # Verify hostname
        context.verify_mode = ssl.CERT_REQUIRED  # Require certificate verification

        with request.urlopen(url, context=context, timeout=10) as response:  # Added timeout
            if response.getcode() != 200:
                logging.error(f"HTTP Error: {response.getcode()} for URL: {url}")  # Log the error
                raise ValueError(f"HTTP Error: {response.getcode()}")

            # Check Content-Length header to prevent large payloads
            content_length = response.getheader('Content-Length')
            if content_length and int(content_length) > MAX_JSON_SIZE:
                logging.error(f"JSON payload too large (Content-Length: {content_length} bytes). Max allowed: {MAX_JSON_SIZE} bytes.")
                raise ValueError(f"JSON payload too large. Max allowed: {MAX_JSON_SIZE} bytes.")

            data = response.read()

            # Check data length after reading, in case Content-Length is missing or incorrect
            if len(data) > MAX_JSON_SIZE:
                logging.error(f"JSON payload too large (actual size: {len(data)} bytes). Max allowed: {MAX_JSON_SIZE} bytes.")
                raise ValueError(f"JSON payload too large. Max allowed: {MAX_JSON_SIZE} bytes.")


            data_str = data.decode('utf-8')  # Decode to string

            # Integrity Check (HMAC)
            if expected_hash:
                calculated_hash = calculate_hmac(data, HMAC_SECRET)
                if not hmac.compare_digest(calculated_hash, expected_hash):
                    logging.error(f"Integrity check failed for URL: {url} - HMAC hash mismatch.")  # Log the error
                    raise ValueError("Integrity check failed: HMAC hash mismatch.")
                logging.info(f"Integrity check passed for URL: {url}")  # Log success

            # Safe Deserialization and Schema Validation
            try:
                json_data = json.loads(data_str)  # Use json.loads for safe deserialization
                jsonschema.validate(instance=json_data, schema=JSON_SCHEMA)  # Validate against schema
                return json_data
            except json.JSONDecodeError as e:
                logging.error(f"Invalid JSON data for URL: {url} - {e}")  # Log the error
                raise ValueError(f"Invalid JSON data: {e}")
            except jsonschema.exceptions.ValidationError as e:
                logging.error(f"JSON schema validation failed for URL: {url} - {e}")  # Log the error
                raise ValueError(f"JSON schema validation failed: {e}")

    except (ValueError, request.URLError, ssl.SSLError) as e:
        logging.error(f"Error reading JSON from URL: {url} - {e}")  # Log the error
        raise  # Re-raise the exception to be handled by the caller


# Example Usage (Illustrative - Replace with your actual URL and expected hash)
if __name__ == '__main__':
    test_url = "https://example.com/data.json"  # Replace with a safe, controlled URL
    # Create a dummy JSON file for testing
    test_data = {"message": "Hello, world!", "value": 123}
    test_data_str = json.dumps(test_data).encode('utf-8')
    expected_hash = calculate_hmac(test_data_str, HMAC_SECRET)  # Calculate the expected hash

    # In a real application, you would fetch the JSON from the URL and calculate the hash.
    # For this example, we'll simulate reading from a file.
    try:
        # This part simulates reading from a URL.  In a real application, you'd use urllib.request.urlopen
        # to fetch the data.  For this example, we'll just use the test_data_str.
        # To make this runnable, we'll write the test data to a file and then read it back.
        # Use tempfile for secure temporary file creation
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(test_data_str)
            temp_file_path = temp_file.name

        with open(temp_file_path, "r") as f:
            json_content = f.read()

        # Simulate the response from urllib.request.urlopen
        class MockResponse:
            def __init__(self, content, code=200, headers={}):
                self.content = content
                self.code = code
                self.headers = headers

            def read(self):
                return self.content.encode('utf-8')

            def getcode(self):
                return self.code

            def getheader(self, name):
                return self.headers.get(name)


        # Mock the urllib.request.urlopen function
        def mock_urlopen(url, context=None):
            headers = {'Content-Length': str(len(json_content))}  # Simulate Content-Length header
            return MockResponse(json_content, headers=headers)

        # Replace the actual urlopen with the mock
        request.urlopen = mock_urlopen

        # Now call the readJSON function
        data = readJSON(test_url, expected_hash=expected_hash)  # Pass expected_hash
        print("Successfully read JSON:", data)

    except ValueError as e:
        print(f"Error processing JSON: {e}")
    finally:
        # Clean up the test file
        if 'temp_file_path' in locals(): # Check if temp_file_path is defined
            try:
                os.remove(temp_file_path)
            except FileNotFoundError:
                pass
            except OSError as e:  # Catch other potential errors during file removal
                logging.error(f"Error removing temporary file: {e}")

