import hmac
import hashlib
import json
import base64
import os
from typing import Any, Dict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a secret key for HMAC.  Store this securely (e.g., environment variable).
SECRET_KEY = os.environ.get("PICKLE_HMAC_SECRET")  # Get from environment

if not SECRET_KEY:
    logging.critical("PICKLE_HMAC_SECRET environment variable not set.  Exiting.")
    raise ValueError("PICKLE_HMAC_SECRET environment variable must be set.")

SECRET_KEY = SECRET_KEY.encode()  # Ensure it's bytes

# Define an allowlist of allowed classes for deserialization.  This is CRITICAL.
ALLOWED_CLASSES = {
    "SafePayload": SafePayload,  # Example:  Allow a class named SafePayload
    # "AnotherSafeClass": AnotherSafeClass,  # Add other classes here
}


class SafePayload(object):
    def __init__(self, data: Dict[str, Any]):
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary.")

        if "message" not in data or not isinstance(data["message"], str):
            raise ValueError("Message must be a string.")

        if "value" not in data or not isinstance(data["value"], int):
            raise ValueError("Value must be an integer.")

        if data["value"] < 0 or data["value"] > 1000:
            raise ValueError("Value must be between 0 and 1000.")

        self.data = {"message": data["message"], "value": data["value"]} # Only store validated data

    def __repr__(self):
        return f"SafePayload({self.data})"


def serialize_data(data: Dict[str, Any]) -> str:
    """
    Safely serializes data using JSON and adds an HMAC for integrity.

    Args:
        data: The data to serialize (must be JSON-serializable).

    Returns:
        A JSON string containing the data and the HMAC.
    """
    data_json = json.dumps(data, sort_keys=True)  # Sort keys for consistent HMAC
    hmac_value = hmac.new(SECRET_KEY, data_json.encode('utf-8'), hashlib.sha256).hexdigest()
    return json.dumps({"data": data_json, "hmac": hmac_value})


def deserialize_data(serialized_data: str) -> Any:
    """
    Safely deserializes data from a JSON string, verifies the HMAC, and checks the class.

    Args:
        serialized_data: The JSON string containing the data and HMAC.

    Returns:
        The deserialized data as an object of the allowed class, or None if deserialization fails.
    """
    try:
        serialized_dict = json.loads(serialized_data)
        data_json = serialized_dict.get("data")
        hmac_received = serialized_dict.get("hmac")

        if not data_json or not hmac_received:
            logging.warning("Missing 'data' or 'hmac' in serialized data.")  # Downgraded to warning
            return None

        # Verify HMAC
        hmac_calculated = hmac.new(SECRET_KEY, data_json.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(hmac_calculated, hmac_received):
            logging.warning("HMAC verification failed.")  # Downgraded to warning
            return None

        # Deserialize the data
        data = json.loads(data_json)

        # Class validation (CRITICAL SECURITY STEP)
        if not isinstance(data, dict) or "class" not in data or "attributes" not in data:
            logging.warning("Invalid data format. Expected a dictionary with 'class' and 'attributes'.") # Downgraded to warning
            return None

        class_name = data["class"]
        attributes = data["attributes"]

        if class_name not in ALLOWED_CLASSES:
            logging.warning(f"Class '{class_name}' is not allowed for deserialization.") # Downgraded to warning
            return None

        # Strict validation: Check for unexpected keys in the attributes
        allowed_attribute_names = ALLOWED_CLASSES[class_name].__init__.__code__.co_varnames[1:]  # Get argument names from __init__
        for key in attributes:
            if key not in allowed_attribute_names:
                logging.warning(f"Unexpected attribute '{key}' for class '{class_name}'.") # Downgraded to warning
                return None


        try:
            # Instantiate the allowed class using the class itself
            return ALLOWED_CLASSES[class_name](**attributes) # Use keyword arguments
        except ValueError as e:
            logging.warning(f"Validation error during instantiation of {class_name}: {e}") # Downgraded to warning
            return None
        except Exception as e:
            logging.error(f"Error during instantiation of {class_name}: {e}")
            return None


    except json.JSONDecodeError:
        logging.warning("Invalid JSON format.") # Downgraded to warning
        return None
    except Exception as e:
        logging.error(f"Error during deserialization: {e}")
        return None


def makePickleData(payload: SafePayload) -> str:
    """
    Safely serializes a SafePayload object using JSON and HMAC.

    Args:
        payload: The SafePayload object to serialize.

    Returns:
        A JSON string containing the serialized data and the HMAC.
    """
    data = {
        "class": "SafePayload",
        "attributes": payload.data
    }
    return serialize_data(data)


# Example Usage (Safe)
if __name__ == '__main__':
    # Create a safe payload
    safe_data = {"message": "Hello, world!", "value": 123}
    safe_payload = SafePayload(safe_data)

    # Serialize the safe payload
    serialized_payload = makePickleData(safe_payload)
    print(f"Serialized payload: {serialized_payload}")

    # Deserialize the safe payload
    deserialized_payload = deserialize_data(serialized_payload)

    if deserialized_payload:
        print(f"Deserialized payload: {deserialized_payload}")
        print(f"Deserialized data: {deserialized_payload.data}")  # Access the data
    else:
        print("Deserialization failed.")

    # Example of an attempt to deserialize an unsafe payload (will fail)
    unsafe_data = '{"class": "UnsafeClass", "attributes": {"command": "rm -rf /"}}'
    unsafe_serialized = serialize_data(json.loads(unsafe_data)) # Simulate serialization
    deserialized_unsafe = deserialize_data(unsafe_serialized)

    if deserialized_unsafe:
        print("Unsafe deserialization succeeded (this should not happen!)")
    else:
        print("Unsafe deserialization failed as expected.")

    # Example of tampering with the data (HMAC will fail)
    tampered_data = serialized_payload.replace("Hello, world!", "Goodbye, world!")
    deserialized_tampered = deserialize_data(tampered_data)

    if deserialized_tampered:
        print("Tampered deserialization succeeded (this should not happen!)")
    else:
        print("Tampered deserialization failed as expected.")

    # Example of invalid data (attribute validation will fail)
    invalid_data = '{"class": "SafePayload", "attributes": {"message": 123, "value": "abc"}}'
    deserialized_invalid = deserialize_data(serialize_data(json.loads(invalid_data)))

    if deserialized_invalid:
        print("Invalid deserialization succeeded (this should not happen!)")
    else:
        print("Invalid deserialization failed as expected.")

