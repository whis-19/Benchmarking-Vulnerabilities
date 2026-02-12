import pickle
import hmac
import hashlib
import secrets
import os
from cryptography.fernet import Fernet
import base64

# (Assuming FERNET_KEY and HMAC_KEY are set in the environment)
FERNET_KEY = os.environ.get("FERNET_KEY").encode()
HMAC_KEY = base64.b64decode(os.environ.get("HMAC_KEY"))

fernet = Fernet(FERNET_KEY)

def secure_serialize(data, hmac_key, fernet):
    serialized_data = pickle.dumps(data)
    encrypted_data = fernet.encrypt(serialized_data)
    
    # Calculate HMAC
    hmac_obj = hmac.new(hmac_key, encrypted_data, hashlib.sha256)
    hmac_digest = hmac_obj.digest()
    
    return hmac_digest + encrypted_data  # Prepend HMAC to the encrypted data

# Example data to serialize
data = {"message": "Hello, world!", "count": 123}

# Securely serialize the data
serialized_data = secure_serialize(data, HMAC_KEY, fernet)

# Convert to hex for transmission (as in the Flask example)
hex_encoded_data = serialized_data.hex()

print(f"Hex-encoded serialized data: {hex_encoded_data}")

# Now you would send this hex_encoded_data to the /process_data endpoint

