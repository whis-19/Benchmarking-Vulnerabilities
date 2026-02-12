from django.conf.urls import url
import pickle
import hashlib
import hmac
import json
import base64

# --- Secure Deserialization ---

def getPickleData(pickled, secret_key, allowed_classes=None):
    """
    Return deserialized data securely.  This function implements several
    security measures to prevent arbitrary code execution during deserialization.

    Args:
        pickled (bytes): The pickled data as bytes.
        secret_key (str): A secret key used for HMAC integrity checking.  This MUST be a strong, randomly generated key.
        allowed_classes (set, optional): A set of allowed classes to deserialize.
                                          If None, deserialization is disabled.  It's HIGHLY recommended to provide a whitelist.

    Returns:
        The deserialized data, or None if deserialization fails.
    """

    if allowed_classes is None or not isinstance(allowed_classes, set):
        print("WARNING: Deserialization is disabled because allowed_classes is not a set or is None.  Returning None.")
        return None

    try:
        # 1. Verify Integrity using HMAC
        signature, data = pickled.split(b"||HMAC||", 1)
        expected_signature = hmac.new(
            secret_key.encode('utf-8'),
            data,
            hashlib.sha256
        ).hexdigest().encode('utf-8')

        if not hmac.compare_digest(signature, expected_signature):
            print("ERROR: HMAC signature verification failed.  Data may be tampered with.")
            return None

        # 2. Restrict Gadget Chains and Deserialize Only Allowed Classes
        class RestrictedUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                if module + '.' + name in allowed_classes:
                    return super().find_class(module, name)
                raise pickle.UnpicklingError(f"Attempted to load unsafe class {module}.{name}")

        # 3. Deserialize the data
        unpickler = RestrictedUnpickler(io.BytesIO(data))  # Use io.BytesIO for in-memory bytes
        data = unpickler.load()
        return data

    except (ValueError, hmac.InvalidTag, pickle.UnpicklingError) as e:
        print(f"ERROR: Deserialization failed: {e}")
        return None
    except Exception as e:
        print(f"ERROR: Unexpected error during deserialization: {e}")
        return None


def serialize_data(data, secret_key):
    """
    Serializes data and adds an HMAC signature for integrity.

    Args:
        data: The data to serialize.
        secret_key (str): A secret key used for HMAC signing.

    Returns:
        bytes: The serialized data with HMAC signature.
    """
    try:
        pickled_data = pickle.dumps(data)
        signature = hmac.new(
            secret_key.encode('utf-8'),
            pickled_data,
            hashlib.sha256
        ).hexdigest().encode('utf-8')
        return signature + b"||HMAC||" + pickled_data
    except Exception as e:
        print(f"ERROR: Serialization failed: {e}")
        return None


# --- Example Usage (with whitelisting) ---
if __name__ == '__main__':
    import io

    # Define a safe class (e.g., a simple data class)
    class MySafeClass:
        def __init__(self, value):
            self.value = value
        def __repr__(self):
            return f"MySafeClass(value={self.value})"

    # Example data
    data_to_serialize = MySafeClass(10)

    # Secret key (MUST be randomly generated and kept secret)
    SECRET_KEY = "your_secret_key_here"  # Replace with a strong, random key

    # Serialize the data
    serialized_data = serialize_data(data_to_serialize, SECRET_KEY)

    if serialized_data:
        # Define allowed classes (whitelist)
        allowed_classes = {
            '__main__.MySafeClass'  #  Module and class name
        }

        # Deserialize the data securely
        deserialized_data = getPickleData(serialized_data, SECRET_KEY, allowed_classes)

        if deserialized_data:
            print("Deserialized data:", deserialized_data)
        else:
            print("Deserialization failed.")

        # Example of trying to deserialize an unsafe class (will fail)
        class UnsafeClass:
            def __reduce__(self):
                import os
                return (os.system, ('echo "Exploit!"',))

        unsafe_data = serialize_data(UnsafeClass(), SECRET_KEY)
        unsafe_deserialized = getPickleData(unsafe_data, SECRET_KEY, allowed_classes) # allowed_classes does NOT contain UnsafeClass

        if unsafe_deserialized:
            print("Unsafe deserialization succeeded (this should not happen!)")
        else:
            print("Unsafe deserialization prevented (as expected).")

    else:
        print("Serialization failed.")


# --- Alternative: JSON Serialization (Recommended) ---

def serialize_to_json(data):
    """Serializes data to JSON format."""
    try:
        return json.dumps(data)
    except TypeError as e:
        print(f"Error serializing to JSON: {e}")
        return None

def deserialize_from_json(json_string):
    """Deserializes data from JSON format."""
    try:
        return json.loads(json_string)
    except json.JSONDecodeError as e:
        print(f"Error deserializing from JSON: {e}")
        return None


# --- URL Handling (Example - Django view) ---
from urllib.parse import urlparse

def my_view(request):
    url = request.GET.get('url')
    if url:
        try:
            parsed_url = urlparse(url)

            # Check scheme (HTTPS is preferred)
            if parsed_url.scheme != 'https':
                print("WARNING: URL scheme is not HTTPS.")
                # Consider rejecting the URL or logging a warning

            # Validate hostname (example: allow only specific domains)
            allowed_domains = ['example.com', 'secure.example.org']
            hostname = parsed_url.hostname
            if hostname not in allowed_domains:
                print(f"ERROR: Hostname {hostname} is not allowed.")
                return HttpResponseBadRequest("Invalid hostname")

            # Handle arbitrary subdomains correctly (if needed)
            # Example: Allow *.example.com
            if hostname.endswith('.example.com'):
                pass # Allow it
            else:
                pass # Not allowed

            # Further processing of the URL (if valid)
            print(f"Processing URL: {url}")
            # ... your code here ...

        except Exception as e:
            print(f"ERROR: Invalid URL: {e}")
            return HttpResponseBadRequest("Invalid URL")

    return HttpResponse("OK")

