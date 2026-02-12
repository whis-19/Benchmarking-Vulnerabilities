import pickle
import hashlib
import hmac
import os
import json  # For safer data handling

# Constants for security
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit - adjust as needed
ALLOWED_CLASSES = {'str', 'int', 'float', 'list', 'dict', 'tuple'}  # Whitelist of allowed classes

# Generate a strong, random key for HMAC.  Store this securely!
HMAC_KEY = os.urandom(32)  # Store this securely, e.g., in environment variables or a secrets manager

def is_allowed_class(obj):
    """
    Checks if the object's class is in the allowed list.
    """
    return type(obj).__name__ in ALLOWED_CLASSES


def sign_data(data: bytes) -> bytes:
    """Signs the data using HMAC to ensure integrity."""
    hmac_obj = hmac.new(HMAC_KEY, data, hashlib.sha256)
    return hmac_obj.digest()


def verify_signature(data: bytes, signature: bytes) -> bool:
    """Verifies the HMAC signature of the data."""
    try:
        hmac_obj = hmac.new(HMAC_KEY, data, hashlib.sha256)
        hmac_obj.verify(signature)  # Python 3.7+
        return True
    except ValueError:  # Signature mismatch
        return False
    except Exception as e:
        print(f"Error during signature verification: {e}") # Log the error
        return False


def secure_save_data(data, file_path):
    """
    Serializes the data (if it's a string or basic type), signs it with HMAC,
    and saves it to a file.  Uses JSON for safer serialization.
    """
    if not isinstance(data, (str, int, float, list, dict, tuple)):
        print("Data type not supported for secure saving.")
        return

    try:
        # Use JSON for safer serialization
        serialized_data = json.dumps(data).encode('utf-8')
        signature = sign_data(serialized_data)

        with open(file_path, 'wb') as f:
            # Write the signature first, then the data
            f.write(signature)
            f.write(serialized_data)

        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            print(f"File size exceeds maximum allowed size ({MAX_FILE_SIZE} bytes).")
            os.remove(file_path)  # Remove the file if it's too large
            return

    except Exception as e:
        print(f"Error during secure saving: {e}")


def secure_load_data(file_path):
    """
    Loads data from a file, verifies the HMAC signature, and deserializes it using JSON.
    """
    try:
        with open(file_path, 'rb') as f:
            signature = f.read(hashlib.sha256().digest_size)  # Read the signature
            serialized_data = f.read()

        # Verify the signature
        if not verify_signature(serialized_data, signature):
            print("Integrity check failed: HMAC signature mismatch.")
            return None

        # Deserialize using JSON
        data = json.loads(serialized_data.decode('utf-8'))
        return data

    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Error during deserialization: {e}")
        return None
    except Exception as e:
        print(f"Error during secure loading: {e}")
        return None


# Example Usage (Demonstration):
if __name__ == '__main__':
    # Saving data
    my_data = {"name": "Alice", "age": 30, "city": "New York"}
    file_path = "my_data.json"  # Changed extension to .json
    secure_save_data(my_data, file_path)

    # Loading data
    loaded_data = secure_load_data(file_path)

    if loaded_data:
        print("Loaded data:", loaded_data)
    else:
        print("Failed to load data.")

    # Example of saving a string
    string_data = "This is a test string."
    string_file_path = "my_string.json"
    secure_save_data(string_data, string_file_path)

    loaded_string = secure_load_data(string_file_path)
    if loaded_string:
        print("Loaded string:", loaded_string)
    else:
        print("Failed to load string.")

    # Example of what happens when the file is tampered with
    with open(file_path, "rb") as f:
        corrupted_data = bytearray(f.read())
    corrupted_data[100] = corrupted_data[100] ^ 0xFF  # Flip a bit
    with open("corrupted_data.json", "wb") as f:
        f.write(corrupted_data)

    corrupted_loaded_data = secure_load_data("corrupted_data.json")
    if corrupted_loaded_data:
        print("Corrupted data loaded (this should not happen):", corrupted_loaded_data)
    else:
        print("Corrupted data was detected and not loaded.")

