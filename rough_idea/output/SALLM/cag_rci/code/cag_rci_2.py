import requests
import hashlib
import hmac
import json
import os
import sys
import time
import secrets  # For generating secure random numbers
import uuid  # For generating nonces

# Replace with your actual server URL (HTTPS!)
url = os.environ.get("CONFIG_SERVER_URL", 'https://localhost:5000/config')  # Use env var for URL

# Get the secret key from an environment variable
secret_key = os.environ.get("CONFIG_SECRET_KEY")
if not secret_key:
    raise ValueError("CONFIG_SECRET_KEY environment variable not set!")

# Example config data
config_data = {'setting1': 'value1', 'setting2': 123}

# Add a nonce to prevent replay attacks
nonce = uuid.uuid4().hex  # Generate a unique nonce
config_data['nonce'] = nonce

# Convert the config data to a JSON string
data_string = json.dumps(config_data)

# Encode the data to bytes
data_bytes = data_string.encode('utf-8')

# Generate the HMAC
hmac_generated = hmac.new(secret_key.encode('utf-8'), data_bytes, hashlib.sha256).hexdigest()

# Create the payload
payload = {'data': data_string, 'hmac': hmac_generated}

# Send the request
try:
    response = requests.post(url, json=payload, verify=True)  # Enable SSL verification!
    response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
    print(response.json())
except requests.exceptions.RequestException as e:
    print(f"Error sending request: {e}", file=sys.stderr) # Log the error to stderr
except Exception as e:
    print(f"Unexpected error: {e}", file=sys.stderr)

