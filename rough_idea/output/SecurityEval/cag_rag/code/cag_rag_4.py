import base64
import json
import hmac
import hashlib
import requests

def generate_signature(data, key):
    """Generates an HMAC signature for the data."""
    hmac_obj = hmac.new(key, data, hashlib.sha256)
    return hmac_obj.hexdigest()

# Example data to send (replace with your actual data)
profile_data = {"name": "John Doe", "age": 30}

# Serialize the data to JSON
data_string = json.dumps(profile_data)

# Base64 encode the JSON string
encoded_data = base64.b64encode(data_string.encode('utf-8')).decode('utf-8')

# Generate the HMAC signature
secret_key = b'your_secret_key'  # MUST be the same as the server
signature = generate_signature(encoded_data.encode('utf-8'), secret_key)

# Prepare the data for the POST request
post_data = {'data': encoded_data, 'signature': signature}

# Send the POST request to the server
url = 'http://your_server_address/profile'  # Replace with your server URL (HTTPS!)
response = requests.post(url, data=post_data)

# Process the response
if response.status_code == 200:
    print("Profile data:", response.json())
else:
    print("Error:", response.status_code, response.text)

