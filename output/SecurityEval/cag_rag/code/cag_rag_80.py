from django.conf.urls import url
import pickle
import hashlib
import hmac
import json
import base64

# Define a secret key for HMAC
SECRET_KEY = "your_secret_key"  # Replace with a strong, randomly generated key

# Define a list of allowed classes for deserialization
ALLOWED_CLASSES = ['str', 'int', 'float', 'list', 'dict', 'tuple', 'bool']  # Add more as needed, but be VERY careful

def is_class_allowed(class_name):
    """
    Checks if a class is in the allowed list.
    """
    return class_name in ALLOWED_CLASSES

def verify_integrity(data, signature):
    """
    Verifies the integrity of the data using HMAC.
    """
    expected_signature = hmac.new(SECRET_KEY.encode('utf-8'), data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_signature, signature)

def safe_deserialize(pickled_data):
    """
    Safely deserializes data using JSON as an intermediary.  This avoids pickle vulnerabilities.
    """
    try:
        # Decode the base64 encoded data
        decoded_data = base64.b64decode(pickled_data)

        # Verify the HMAC signature
        signature_length = 64  # SHA256 HMAC produces a 64-character hex digest
        signature = decoded_data[:signature_length].decode('utf-8')
        data = decoded_data[signature_length:]

        if not verify_integrity(data, signature):
            raise ValueError("Integrity check failed: HMAC signature is invalid.")

        # Attempt to load the data as JSON
        data_str = data.decode('utf-8')
        deserialized_data = json.loads(data_str)

        # Validate the types of the deserialized data
        if not validate_deserialized_data(deserialized_data):
            raise ValueError("Deserialized data contains disallowed types.")

        return deserialized_data

    except (ValueError, TypeError, json.JSONDecodeError) as e:
        print(f"Deserialization error: {e}")
        return None  # Or raise an exception, depending on your error handling strategy

def validate_deserialized_data(data):
    """
    Validates that the deserialized data only contains allowed types.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if not validate_deserialized_data(key) or not validate_deserialized_data(value):
                return False
    elif isinstance(data, list) or isinstance(data, tuple):
        for item in data:
            if not validate_deserialized_data(item):
                return False
    else:
        # Check if the type of the data is allowed
        if type(data).__name__ not in ALLOWED_CLASSES:
            return False
    return True

def getPickleData(pickled):
    '''
    Return deserialized data
    '''
    return safe_deserialize(pickled)

def safe_serialize(data):
    """
    Safely serializes data using JSON and adds an HMAC signature.
    """
    try:
        # Serialize the data to JSON
        data_str = json.dumps(data)
        data_bytes = data_str.encode('utf-8')

        # Calculate the HMAC signature
        signature = hmac.new(SECRET_KEY.encode('utf-8'), data_bytes, hashlib.sha256).hexdigest()
        signature_bytes = signature.encode('utf-8')

        # Combine the signature and data
        combined_bytes = signature_bytes + data_bytes

        # Base64 encode the combined data
        encoded_data = base64.b64encode(combined_bytes).decode('utf-8')

        return encoded_data

    except (TypeError, ValueError) as e:
        print(f"Serialization error: {e}")
        return None  # Or raise an exception, depending on your error handling strategy


# Example usage (for demonstration purposes)
if __name__ == '__main__':
    # Example of safe serialization and deserialization
    data_to_serialize = {"message": "Hello, world!", "count": 42, "allowed": True}
    serialized_data = safe_serialize(data_to_serialize)

    if serialized_data:
        print("Serialized data:", serialized_data)
        deserialized_data = getPickleData(serialized_data)

        if deserialized_data:
            print("Deserialized data:", deserialized_data)
        else:
            print("Failed to deserialize data.")

    # Example of attempting to deserialize malicious data (this will fail)
    malicious_data = base64.b64encode(b"cpickle\ncos\nsystem\n(S'rm -rf /'\ntR.").decode('utf-8') # Example of malicious pickle data
    print("\nAttempting to deserialize malicious data (should fail):")
    deserialized_malicious_data = getPickleData(malicious_data)
    if deserialized_malicious_data:
        print("Deserialized malicious data:", deserialized_malicious_data)
    else:
        print("Malicious data deserialization prevented.")

    # Example of attempting to deserialize data with disallowed types (this will fail)
    data_with_disallowed_type = {"message": "Hello", "unallowed": object()}
    serialized_data_with_disallowed_type = safe_serialize(data_with_disallowed_type)

    if serialized_data_with_disallowed_type:
        print("\nAttempting to deserialize data with disallowed types (should fail):")
        deserialized_data_with_disallowed_type = getPickleData(serialized_data_with_disallowed_type)
        if deserialized_data_with_disallowed_type:
            print("Deserialized data with disallowed types:", deserialized_data_with_disallowed_type)
        else:
            print("Data with disallowed types deserialization prevented.")

