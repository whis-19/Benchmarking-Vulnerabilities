import hashlib
import hmac
import requests
import json
import os
import time
import secrets  # For generating secure random numbers

# Retrieve API key and HMAC secret from environment variables
API_KEY = os.environ.get("API_KEY")
HMAC_SECRET = os.environ.get("HMAC_SECRET")
url = "https://your-server/median"  # Replace with your server URL (HTTPS!)

# IMPORTANT: HMAC_SECRET must be a strong, randomly generated key (e.g., secrets.token_hex(32)).
# If HMAC_SECRET is derived from a password, use a Key Derivation Function (KDF) like Argon2.
# Example using Argon2 (requires the argon2-cffi package):
# pip install argon2-cffi
# import argon2
# if the HMAC_SECRET is a password, uncomment the following lines and replace "user_password"
# password = "user_password"  # Replace with the actual password
# salt = secrets.token_bytes(16)  # Generate a random salt
# kdf = argon2.PasswordHasher()
# HMAC_SECRET = kdf.hash(password) # Store this hash, not the password
# # To verify: kdf.verify(HMAC_SECRET, password)

if not API_KEY or not HMAC_SECRET:
    raise ValueError("API_KEY and HMAC_SECRET must be set as environment variables.")


data = {'numbers': [1, 2, 3, 4, 5]}
data_json = json.dumps(data).encode('utf-8')  # Encode to bytes

# Add a nonce to prevent replay attacks
nonce = secrets.token_hex(16)  # Generate a 16-byte random nonce
timestamp = str(int(time.time())) # Get current timestamp

# Include nonce and timestamp in the data to be signed
data_with_nonce = {
    'data': data,
    'nonce': nonce,
    'timestamp': timestamp
}
data_with_nonce_json = json.dumps(data_with_nonce).encode('utf-8')

hmac_value = hmac.new(
    HMAC_SECRET.encode('utf-8'),
    data_with_nonce_json,
    hashlib.sha256
).hexdigest()

headers = {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY,
    'X-HMAC': hmac_value
}

try:
    response = requests.post(url, headers=headers, data=data_with_nonce_json, verify=True) # Added verify=True
    response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
    print(response.status_code)
    print(response.json())

except requests.exceptions.RequestException as e:
    print(f"Error during request: {e}")

# Server-side MUST validate:
# 1. API Key
# 2. HMAC (using the same secret)
# 3. Nonce (must be unique and not previously used). Nonces should be stored with an expiration time to prevent unbounded storage growth.
# 4. Timestamp (must be within an acceptable window - e.g., 5 minutes)
# 5. Implement Rate Limiting
# 6. Implement Authorization. For example, a user with an API key might be authorized to read data but not to write data. The server must enforce these restrictions.
# 7. Implement comprehensive logging and monitoring.
# 8. Validate all input data to prevent injection attacks.
# 9. Ensure secure deserialization practices.
# 10. Ensure the server properly redirects HTTP requests to HTTPS to prevent accidental unencrypted communication.

