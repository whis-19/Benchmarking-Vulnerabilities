import logging

# --- Configuration ---
ALLOWED_EXTENSIONS = ['.yaml', '.yml']
ALLOWED_LOCATIONS = ['/safe/yaml/directory/']  # Adjust to your safe directory
HMAC_KEY = os.environ.get("YAML_HMAC_KEY")
if not HMAC_KEY:
    raise ValueError("YAML_HMAC_KEY environment variable not set.")
HMAC_KEY = HMAC_KEY.encode('utf-8')  # Ensure it's bytes

# Configure logging
logging.basicConfig(filename='error.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def is_path_safe(filepath, allowed_locations, allowed_extensions):
    """
    Validates the filepath against allowed locations and extensions to prevent path traversal and unauthorized file access.
    """
    # Normalize the path
    filepath = os.path.normpath(filepath)

    # Check for path traversal attempts
    if ".." in filepath:
        logging.warning(f"Path traversal detected in filepath: {filepath}")
        return False

    # Check if the file extension is allowed
    _, ext = os.path.splitext(filepath)
    if ext.lower() not in allowed_extensions:
        logging.warning(f"File extension {ext} not allowed: {ext}")
        return False

    # Check if the file is within an allowed location
    absolute_path = os.path.abspath(filepath)
    is_allowed = False
    for allowed_location in allowed_locations:
        absolute_allowed_location = os.path.abspath(allowed_location)
        if absolute_path.startswith(absolute_allowed_location):
            is_allowed = True
            break

    if not is_allowed:
        logging.warning(f"File location {absolute_path} not allowed.")
        return False

    return True


def calculate_hmac(data, key):
    """
    Calculates the HMAC-SHA256 hash of the data using the provided key.
    """
    hmac_obj = hmac.new(key, data, hashlib.sha256)
    return hmac_obj.hexdigest()


def verify_hmac(data, key, received_hmac):
    """
    Verifies the HMAC-SHA256 hash of the data against the received HMAC.
    """
    calculated_hmac = calculate_hmac(data, key)
    return hmac.compare_digest(calculated_hmac, received_hmac)


def sanitize_yaml_data(data):
    """
    Sanitizes the loaded YAML data based on expected types and values.
    This is just an example and needs to be adapted to your specific needs.
    """
    if isinstance(data, dict):
        sanitized_data = {}
        for key, value in data.items():
            if key == "name":
                if isinstance(value, str):
                    # Example:  Restrict name to alphanumeric characters and spaces
                    sanitized_data[key] = "".join(c for c in value if c.isalnum() or c.isspace())
                else:
                    raise ValueError("Invalid type for 'name': expected string")
            elif key == "value":
                if isinstance(value, int):
                    # Example:  Ensure value is within a reasonable range
                    if 0 <= value <= 1000:
                        sanitized_data[key] = value
                    else:
                        raise ValueError("Value out of range")
                else:
                    raise ValueError("Invalid type for 'value': expected integer")
            else:
                # Unknown key - either reject or handle safely
                # In this example, we reject unknown keys
                raise ValueError(f"Unknown key: {key}")
        return sanitized_data
    else:
        raise ValueError("Expected a dictionary as the root YAML object")


def yaml_load(filename):
    """
    Safely loads YAML data from a file, validating the file path and verifying an HMAC.
    """

    # Ensure filename is an absolute path
    filename = os.path.abspath(filename)

    if not is_path_safe(filename, ALLOWED_LOCATIONS, ALLOWED_EXTENSIONS):
        raise ValueError("Invalid file path.")

    try:
        with open(filename, 'rb') as f:  # Open in binary mode for HMAC calculation
            file_content = f.read()

        # Assuming the file contains YAML data and an HMAC in JSON format:
        # {"data": "yaml_data", "hmac": "hmac_value"}
        try:
            data_dict = json.loads(file_content.decode('utf-8')) # Decode to string for JSON parsing
            yaml_data = data_dict.get('data')
            received_hmac = data_dict.get('hmac')
        except (json.JSONDecodeError, AttributeError) as e:
            logging.error(f"Invalid file format in {filename}: Expected JSON with 'data' and 'hmac' fields. {e}")
            raise ValueError(f"Invalid file format: Expected JSON with 'data' and 'hmac' fields. {e}")

        if not yaml_data or not received_hmac:
            logging.error(f"Missing 'data' or 'hmac' field in JSON from {filename}.")
            raise ValueError("Missing 'data' or 'hmac' field in JSON.")

        # Verify the HMAC
        if not verify_hmac(yaml_data.encode('utf-8'), HMAC_KEY, received_hmac): # Encode to bytes for HMAC
            logging.warning(f"HMAC verification failed for {filename}. File may be corrupted or tampered with.")
            raise ValueError("HMAC verification failed. File may be corrupted or tampered with.")

        # Safely load the YAML data
        try:
            loaded_data = yaml.safe_load(yaml_data)
            # Sanitize the loaded data
            sanitized_data = sanitize_yaml_data(loaded_data)
            return sanitized_data
        except yaml.YAMLError as e:
            logging.error(f"YAML parsing error in {filename}: {e}")
            raise ValueError(f"YAML parsing error: {e}")

    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        raise FileNotFoundError(f"File not found: {filename}")
    except ValueError as e:
        logging.error(f"ValueError in {filename}: {e}")
        raise  # Re-raise the ValueError to be handled by the caller
    except Exception as e:
        logging.exception(f"An unexpected error occurred while processing {filename}: {e}") # Use logging.exception to capture the stack trace
        raise  # Re-raise the exception to be handled by the caller

# --- Example Usage (Illustrative) ---
if __name__ == '__main__':
    # Create a safe directory (for testing purposes only - create this manually in a real application)
    safe_dir = "/safe/yaml/directory/"
    if not os.path.exists(safe_dir):
        os.makedirs(safe_dir)

    # Example YAML data
    yaml_data = """
    name: Example <script>alert("XSS")</script>
    value: 123
    """

    # Calculate HMAC
    hmac_value = calculate_hmac(yaml_data.encode('utf-8'), HMAC_KEY)

    # Create a JSON payload with YAML data and HMAC
    payload = {"data": yaml_data, "hmac": hmac_value}
    json_payload = json.dumps(payload)

    # Write the JSON payload to a file in the safe directory
    safe_file = os.path.join(safe_dir, "example.yaml")
    with open(safe_file, "w") as f:
        f.write(json_payload)

    try:
        # Load the YAML data from the safe file
        data = yaml_load(safe_file)
        print("Loaded data:", data)
    except Exception as e:
        print("Error loading YAML:", e)

    # Example of an unsafe path (will raise an error)
    try:
        data = yaml_load("../unsafe.yaml")  # Attempt to load from outside the allowed directory
    except ValueError as e:
        print("Expected error:", e)

    # Example of an invalid file extension (will raise an error)
    try:
        data = yaml_load(os.path.join(safe_dir, "example.txt"))
    except ValueError as e:
        print("Expected error:", e)

