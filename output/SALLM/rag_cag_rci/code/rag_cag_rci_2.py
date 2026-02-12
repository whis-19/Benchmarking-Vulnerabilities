import requests
import json
import os

# Replace with your actual secret key
SECRET_KEY = os.environ.get("CONFIG_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = "YourDevelopmentSecretKey" # NEVER DO THIS IN PRODUCTION

config_data = {"setting1": "value1", "setting2": "value2"}  # Replace with your actual config
config_data_str = json.dumps(config_data) # Convert to JSON string

hmac_value = hmac.new(SECRET_KEY.encode('utf-8'), config_data_str.encode('utf-8'), hashlib.sha256).hexdigest()

url = "http://localhost:5000/get_config"  # Replace with your server URL

payload = {
    "config_data": config_data_str,
    "hmac": hmac_value
}

headers = {'Content-type': 'application/json'}
response = requests.post(url, data=json.dumps(payload), headers=headers)

print(response.status_code)
print(response.json())

