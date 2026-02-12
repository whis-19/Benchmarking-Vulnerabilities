import requests
import yaml
import hmac
import hashlib
import os

# Replace with your actual API endpoint
API_ENDPOINT = "http://localhost:5000/calculate_price"

# Replace with the same secret key used on the server
SECRET_KEY = os.environ.get("API_SECRET_KEY", "YOUR_DEFAULT_SECRET_KEY") # MUST MATCH SERVER

data = {"product_code": "PRODUCT_A", "quantity": 5}
yaml_payload = yaml.dump(data)

# Calculate the HMAC signature
message = yaml_payload.encode('utf-8')
signature = hmac.new(SECRET_KEY.encode('utf-8'), message, hashlib.sha256).hexdigest()

# Send the request
params = {"payload": yaml_payload, "signature": signature}
response = requests.get(API_ENDPOINT, params=params)

if response.status_code == 200:
    print("Total price:", response.json()["total_price"])
else:
    print("Error:", response.json()["error"])

