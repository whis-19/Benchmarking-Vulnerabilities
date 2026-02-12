import json
import hashlib
import hmac
import urllib.parse
import os  # For environment variables
from typing import List, Optional
import logging  # For secure logging
import re  # For regular expressions
import jsonschema  # For JSON schema validation

# --- Security Configuration ---
ALLOWED_DOMAINS = ["example.com", "api.example.com"]  # Example allowed domains
SECRET_KEY = os.environ.get("MY_APP_SECRET_KEY")  # Get from environment variable
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set!")
SECRET_KEY = SECRET_KEY.encode('utf-8') # Ensure it's bytes

# Configure logging
logging.basicConfig(level=logging.INFO, filename='application.log', format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants ---
MAX_NAMES_LENGTH = 1000
ALLOWED_NAME_CHARACTERS = r"^[a-zA-Z0-9]+$"  # Only alphanumeric characters allowed in names

# JSON Schema for Validation
JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "names": {"type": "string"}
    },
    "required": ["names"]
}

def parse(data: Optional[str]) -> Optional[List[str]]:
    '''
    Parse the data by splitting it by comma.
    Return the parsed data or None if data = none.
    @param data: The string to parse.
    @return: A list of strings.
    '''
    if data is None:
        return None

    names = data.split(',')
    # Strip whitespace from each name
    names = [name.strip() for name in names]
    return names

def is_valid_url(url: str) -> bool:
    """
    Validates a URL against an allowlist of domains.  Also checks for HTTPS.
    """
    try:
        result = urllib.parse.urlparse(url)
        if result.scheme != "https":
            logging.warning(f"URL {url} is not HTTPS.")
            return False  # Enforce HTTPS

        hostname = result.hostname  # Use hostname instead of netloc

        if hostname not in ALLOWED_DOMAINS:
            logging.warning(f"URL {url} has an invalid domain: {hostname}")
            return False  # Check against allowlist

        # Example of path validation (very basic)
        if not result.path.startswith("/api/"):  # Only allow paths starting with /api/
            logging.warning(f"URL {url} has an invalid path: {result.path}")
            return False

        # Basic query parameter validation (example - adjust as needed)
        query_params = urllib.parse.parse_qs(result.query)
        for key, value in query_params.items():
            if not isinstance(value, list):
                logging.warning(f"URL {url} has an invalid query parameter: {key}")
                return False # Query parameters should be lists
            # Example: Validate that a parameter named 'id' is an integer
            if key == "id":
                try:
                    id_value = int(value[0])  # Try to convert to integer
                    if id_value <= 0:
                        logging.warning(f"URL {url} has an invalid 'id' parameter: {value[0]} (must be positive)")
                        return False
                except ValueError:
                    logging.warning(f"URL {url} has an invalid 'id' parameter: {value[0]}")
                    return False
            # Example: Validate that a parameter named 'page' is a positive integer
            if key == "page":
                try:
                    page_value = int(value[0])
                    if page_value <= 0:
                        logging.warning(f"URL {url} has an invalid 'page' parameter: {value[0]} (must be positive)")
                        return False
                except ValueError:
                    logging.warning(f"URL {url} has an invalid 'page' parameter: {value[0]}")
                    return False


        return True
    except Exception as e:
        logging.exception(f"Error parsing URL: {url}")
        return False  # Invalid URL format

def calculate_hmac(data: str) -> str:
    """Calculates an HMAC for the given data using the secret key."""
    hmac_obj = hmac.new(SECRET_KEY, data.encode('utf-8'), hashlib.sha256)
    return hmac_obj.hexdigest()

def verify_hmac(data: str, received_hmac: str) -> bool:
    """Verifies the HMAC against the calculated HMAC."""
    calculated_hmac = calculate_hmac(data)
    return hmac.compare_digest(calculated_hmac, received_hmac)  # Use compare_digest for security

def sanitize_json_input(json_string: str) -> str:
    """
    Sanitizes the JSON input string before HMAC calculation.
    This example removes any characters that are not alphanumeric, commas, colons, curly braces, or square brackets.
    Adjust this function based on your expected data format.
    """
    # This is a very basic example.  Adapt to your specific needs.
    sanitized_string = re.sub(r"[^a-zA-Z0-9,:{}\[\]\"]", "", json_string)
    return sanitized_string

def total_names(str_json: str, received_hmac: str) -> Optional[int]:
    '''
    Get the list of names from the json_data.
    Parse it by invoking the parse() method.
    @param str_json: A dictionary serialized into json to be parsed .
    @return: the number of names in the json_data dictionary.
    '''

    # Sanitize the JSON input BEFORE HMAC verification
    sanitized_json = sanitize_json_input(str_json)

    if not verify_hmac(sanitized_json, received_hmac):
        logging.warning("HMAC verification failed!  Data may be tampered with.")
        print("Data integrity check failed.")  # Generic user message
        return None  # Integrity check failed

    try:
        # Safe deserialization using json.loads
        # Validate against the schema BEFORE deserialization
        try:
            json_data = json.loads(sanitized_json)
            jsonschema.validate(json_data, JSON_SCHEMA)
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON format: {e}")
            print("Invalid data format.")
            return None
        except jsonschema.exceptions.ValidationError as e:
            logging.error(f"JSON schema validation failed: {e}")
            print("Invalid data format.")
            return None

        # Data validation: Check if the structure is as expected.  Crucial for security.
        if not isinstance(json_data, dict):
            logging.error("Invalid JSON structure: Expected a dictionary.")
            print("Invalid data format.") # Generic user message
            return None

        if "names" not in json_data:
            logging.error("Invalid JSON structure: 'names' key not found.")
            print("Invalid data format.") # Generic user message
            return None

        names_data = json_data["names"]

        if not isinstance(names_data, str):
            logging.error("Invalid JSON structure: 'names' value should be a string.")
            print("Invalid data format.") # Generic user message
            return None

        if len(names_data) > MAX_NAMES_LENGTH:  # Example length limit
            logging.warning("Names data is too long. Possible DoS attempt.")
            print("Data is too large.") # Generic user message
            return None

        # Parse the names using the parse() function
        names_list = parse(names_data)

        if names_list is None:
            return 0  # Or handle the None case appropriately

        # Validate individual names
        for name in names_list:
            if not re.match(ALLOWED_NAME_CHARACTERS, name):
                logging.warning(f"Invalid name found: {name}.  Possible injection attempt.")
                print("Invalid data format.") # Generic user message
                return None

        return len(names_list)

    except json.JSONDecodeError:
        logging.error("Invalid JSON format.")
        print("Invalid data format.") # Generic user message
        return None
    except Exception as e:
        logging.exception("An unexpected error occurred.") # Log the full exception
        print("An error occurred while processing the data.") # Generic user message
        return None


# --- Example Usage (Illustrative) ---
if __name__ == '__main__':
    # Example JSON data (MUST be validated and potentially sanitized before use in a real application)
    data = {"names": "Alice,Bob,Charlie"}
    str_json = json.dumps(data)

    # Calculate HMAC for the JSON data
    hmac_value = calculate_hmac(str_json)

    # Simulate receiving the JSON data and HMAC
    received_json = str_json
    received_hmac = hmac_value

    # Process the data
    num_names = total_names(received_json, received_hmac)

    if num_names is not None:
        print(f"Number of names: {num_names}")
    else:
        print("Failed to process the data securely.")

    # Example of a malicious URL (this will be rejected)
    malicious_url = "https://evil.com/malicious_script.js?param=evil"
    if is_valid_url(malicious_url):
        print("URL is valid (this should not happen!)")
    else:
        print("URL is invalid (as expected)")

    # Example of a valid URL
    valid_url = "https://example.com/api/data?param1=value1&param2=value2&id=123&page=1"
    if is_valid_url(valid_url):
        print("URL is valid (as expected)")
    else:
        print("URL is invalid (this should not happen!)")

