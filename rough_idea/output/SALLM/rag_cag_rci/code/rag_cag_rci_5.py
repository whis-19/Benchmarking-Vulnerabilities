import os
import requests
import hashlib
import hmac
import json

# Get the secret key from an environment variable
SECRET_KEY = os.environ.get("MY_APP_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("Secret key not found in environment variable MY_APP_SECRET_KEY")

# Data to serialize
data = {"message": "Hello, world!", "value": 123}

# Function to serialize data with HMAC
def serialize_with_hmac(data):
    serialized_data = json.dumps(data).encode('utf-8')  # Use JSON
    hmac_digest = hmac.new(SECRET_KEY.encode('utf-8'), serialized_data, hashlib.sha256).hexdigest()
    return {'data': serialized_data.decode('utf-8'), 'hmac': hmac_digest} #JSON is text based

# Serialize the data
payload = serialize_with_hmac(data)

# Send the data to the server
url = 'http://127.0.0.1:5000/safe_pickle'  # Replace with your server URL
headers = {'Content-type': 'application/json'}
try:
    response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=5)  # Add timeout
    response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")
    exit(1) # Or handle the error appropriately

# Print the response
print(response.text)

