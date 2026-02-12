import pickle
import hmac
import hashlib
import json
import urllib.parse
import logging
import os  # For environment variable access
import io  # For BytesIO

# Configure logging (example)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def secure_serialize(data, secret_key):
    """
    Serializes data using pickle and signs it with HMAC for integrity.

    Args:
        data: The data to serialize.
        secret_key: The secret key used for HMAC.  MUST be kept secret.

    Returns:
        A bytes object containing the serialized and signed data, or None on error.
    """
    try:
        serialized_data = pickle.dumps(data)
        hmac_digest = hmac.new(secret_key.encode('utf-8'), serialized_data, hashlib.sha256).digest()
        return hmac_digest + serialized_data
    except Exception as e:
        logging.error(f"Serialization error: {e}")
        return None


def secure_deserialize(data, secret_key, allowed_classes=None):
    """
    Deserializes data, verifying the HMAC signature to ensure integrity and whitelisting allowed classes.

    Args:
        data: The serialized and signed data.
        secret_key: The secret key used for HMAC.  MUST be kept secret.
        allowed_classes: A set of allowed classes for deserialization.  Defaults to a safe subset.

    Returns:
        The deserialized data, or None if the signature is invalid or the class is not allowed.
    """
    if allowed_classes is None:
        allowed_classes = {int, float, str, bool, dict, list, set, type(None)}  # Removed tuple

    if len(data) < hashlib.sha256().digest_size:
        logging.error("Data is too short to contain HMAC.")
        return None

    hmac_digest = data[:hashlib.sha256().digest_size]
    serialized_data = data[hashlib.sha256().digest_size:]

    try:
        expected_hmac = hmac.new(secret_key.encode('utf-8'), serialized_data, hashlib.sha256).digest()
        if not hmac.compare_digest(hmac_digest, expected_hmac):
            logging.error("HMAC signature verification failed.")
            return None

        def find_class(module, name):
            # This is intentionally restricted to prevent arbitrary code execution.
            return None

        class CustomUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                return find_class(module, name)

        unpickler = CustomUnpickler(io.BytesIO(serialized_data))
        data = unpickler.load()

        if not is_type_allowed(data, allowed_classes):
            logging.error("Deserialized object contains disallowed types.")
            return None

        return data
    except Exception as e:
        logging.error(f"Deserialization error: {e}")
        return None


def is_type_allowed(obj, allowed_classes):
    """
    Recursively checks if the type of the object and its contents (if applicable) are in the allowed_classes set.
    For dictionaries, it requires keys to be strings.
    """
    if type(obj) not in allowed_classes:
        return False

    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                return False
            if not is_type_allowed(value, allowed_classes):
                return False
    elif isinstance(obj, list) or isinstance(obj, set):
        for item in obj:
            if not is_type_allowed(item, allowed_classes):
                return False
    # No need to check tuples if they are not in allowed_classes

    return True


def secure_url_check(url_string, allowed_hosts):
    """
    Checks if a URL is safe based on allowed hosts and scheme.

    Args:
        url_string: The URL string to check.
        allowed_hosts: A list of allowed hostnames.

    Returns:
        True if the URL is safe, False otherwise.
    """
    try:
        parsed_url = urllib.parse.urlparse(url_string)

        # Treat relative URLs as safe (within the application)
        if not parsed_url.netloc and not parsed_url.scheme:
            return True

        if not parsed_url.scheme:
            return True  # Treat relative URLs as safe (within the application)

        if parsed_url.scheme not in ['https', 'http']:
            logging.error("Error: Disallowed URL scheme.")
            return False

        if parsed_url.netloc in allowed_hosts:
            return True

        # Allow subdomains of allowed hosts
        for host in allowed_hosts:
            if parsed_url.netloc.endswith("." + host) or parsed_url.netloc == host:
                return True

        logging.warning(f"URL {url_string} is not in the allowed hosts.")
        return False
    except Exception as e:
        logging.error(f"URL parsing error: {e}")
        return False


def secure_get_json_data(request):
    """
    Safely retrieves JSON data from a request, validating the Content-Type header.

    Args:
        request: The request object (e.g., from Flask or Django).  Assumes it has a 'get_data' and 'headers' attribute.

    Returns:
        A dictionary containing the JSON data, or None on error.
    """
    try:
        # Content-Type validation (if applicable to the request object)
        if hasattr(request, 'headers') and 'Content-Type' in request.headers:
            if request.headers['Content-Type'] != 'application/json':
                logging.error("Content-Type is not application/json.")
                return None

        data = json.loads(request.get_data().decode('utf-8'))
        return data
    except json.JSONDecodeError as e:
        logging.error(f"JSON decoding error: {e}")
        return None
    except Exception as e:
        logging.error(f"Error retrieving JSON data: {e}")
        return None


# Example Usage
if __name__ == '__main__':
    # Load the secret key from an environment variable
    secret_key = os.environ.get("MY_SECRET_KEY")
    if not secret_key:
        logging.error("Error: Secret key not found in environment variable MY_SECRET_KEY.")
        exit()

    data = {"message": "Hello, world!", "value": 123}
    serialized_data = secure_serialize(data, secret_key)

    if serialized_data:
        deserialized_data = secure_deserialize(serialized_data, secret_key)
        if deserialized_data:
            print("Deserialized data:", deserialized_data)
        else:
            print("Failed to deserialize data.")

    url_to_check = "https://www.example.com/path"
    allowed_hosts = ["example.com"]
    if secure_url_check(url_to_check, allowed_hosts):
        print(f"URL {url_to_check} is safe.")
    else:
        print(f"URL {url_to_check} is not safe.")

    # Example using JSON (assuming a mock request object)
    class MockRequest:
        def get_data(self):
            return b'{"key": "value"}'

        @property
        def headers(self):
            return {'Content-Type': 'application/json'}


    mock_request = MockRequest()
    json_data = secure_get_json_data(mock_request)
    if json_data:
        print("JSON data:", json_data)
    else:
        print("Failed to retrieve JSON data.")

