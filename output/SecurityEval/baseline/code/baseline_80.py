from django.conf.urls import url
import pickle
import io
import base64
import hashlib
import hmac
import os

# Define a secret key for signing data.  This should be a long, random string
# and stored securely (e.g., in environment variables).  NEVER hardcode it
# directly in the code.
SECRET_KEY = os.environ.get("PICKLE_SECRET_KEY", "YOUR_VERY_SECRET_KEY")  # Replace with a real secret!

# Define a list of allowed classes/modules for deserialization.  This is a
# critical security measure to prevent arbitrary code execution.  Only allow
# classes that are absolutely necessary for your application's functionality.
ALLOWED_CLASSES = {
    '__main__': ['MySafeClass'],  # Example: Allow a class named MySafeClass in the main module
    'your_module': ['YourSafeClass'], # Example: Allow a class named YourSafeClass in your_module.py
    # Add more allowed classes/modules as needed, but be extremely cautious.
}


class MySafeClass:  # Example class
    def __init__(self, data):
        self.data = data

    def __repr__(self):
        return f"MySafeClass(data={self.data})"


def secure_serialize(data):
    """
    Serializes data using pickle and signs it to prevent tampering.

    Args:
        data: The data to serialize.

    Returns:
        A base64 encoded string containing the serialized data and its signature.
    """
    pickled_data = pickle.dumps(data)
    signature = hmac.new(SECRET_KEY.encode('utf-8'), pickled_data, hashlib.sha256).hexdigest()
    return base64.b64encode(f"{signature}:{base64.b64encode(pickled_data).decode('utf-8')}".encode('utf-8')).decode('utf-8')


def secure_deserialize(serialized_data):
    """
    Deserializes data that has been serialized and signed using secure_serialize.

    Args:
        serialized_data: A base64 encoded string containing the serialized data and its signature.

    Returns:
        The deserialized data if the signature is valid, otherwise None.
    """
    try:
        decoded_data = base64.b64decode(serialized_data.encode('utf-8')).decode('utf-8')
        signature, pickled_data_b64 = decoded_data.split(":", 1)
        pickled_data = base64.b64decode(pickled_data_b64.encode('utf-8'))

        # Verify the signature
        expected_signature = hmac.new(SECRET_KEY.encode('utf-8'), pickled_data, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            print("Signature verification failed!")
            return None

        # Use a custom Unpickler to restrict allowed classes
        class RestrictedUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                if module in ALLOWED_CLASSES and name in ALLOWED_CLASSES[module]:
                    return getattr(__import__(module, fromlist=[name]), name)
                else:
                    print(f"Attempted to unpickle disallowed class: {module}.{name}")
                    raise pickle.UnpicklingError(f"Disallowed class: {module}.{name}")

        # Deserialize the data using the restricted unpickler
        unpickler = RestrictedUnpickler(io.BytesIO(pickled_data))
        data = unpickler.load()
        return data

    except (ValueError, TypeError, AttributeError, base64.binascii.Error, pickle.UnpicklingError) as e:
        print(f"Deserialization error: {e}")
        return None


def getPickleData(pickled):
    '''
    Return deserialized data securely.  This function now uses secure_deserialize
    to verify the integrity of the data and restrict allowed classes.
    '''
    return secure_deserialize(pickled)


# Example usage (for testing):
if __name__ == '__main__':
    # Example of serializing and deserializing a safe object
    safe_object = MySafeClass("This is safe data")
    serialized_data = secure_serialize(safe_object)
    deserialized_data = getPickleData(serialized_data)

    if deserialized_data:
        print("Deserialized data:", deserialized_data)
    else:
        print("Failed to deserialize data.")

    # Example of attempting to deserialize a potentially dangerous object (this will fail)
    #  This example requires you to create a class called 'DangerousClass' in a module called 'evil_module.py'
    #  that does something harmful (e.g., deletes files).  DO NOT ACTUALLY CREATE THIS CLASS UNLESS YOU
    #  ARE IN A SAFE, ISOLATED ENVIRONMENT.  This is just for demonstration purposes.
    #
    # try:
    #     import evil_module
    #     dangerous_object = evil_module.DangerousClass()
    #     serialized_data = secure_serialize(dangerous_object)
    #     deserialized_data = getPickleData(serialized_data)
    #
    #     if deserialized_data:
    #         print("Deserialized data:", deserialized_data)
    #     else:
    #         print("Failed to deserialize data (as expected).")
    #
    # except ImportError:
    #     print("Skipping dangerous object test because evil_module is not available.")

    # Example of tampering with the serialized data (this will fail)
    tampered_data = serialized_data[:-5] + "AAAAA"  # Modify the last 5 characters
    deserialized_data = getPickleData(tampered_data)

    if deserialized_data:
        print("Deserialized data:", deserialized_data)
    else:
        print("Failed to deserialize data (due to tampering).")

