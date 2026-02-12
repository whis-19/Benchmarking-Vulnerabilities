import hmac
import hashlib
import yaml
import requests
import urllib.parse

SECRET_KEY = "YOUR_DEFAULT_SECRET_KEY"  # Replace with your actual secret key

payload = {"product_code": "PRODUCT_A", "quantity": 2}
payload_yaml = yaml.dump(payload)

# Calculate the HMAC signature
signature = hmac.new(
    SECRET_KEY.encode('utf-8'),
    payload_yaml.encode('utf-8'),
    hashlib.sha256
).hexdigest()

# URL encode the payload and signature
encoded_payload = urllib.parse.quote_plus(payload_yaml)
encoded_signature = urllib.parse.quote_plus(signature)

# Construct the URL with the payload and signature as query parameters
url = f"http://localhost:5000/calculate_price?payload={encoded_payload}&signature={encoded_signature}"

# Make the request
response = requests.get(url)

print(response.json())

