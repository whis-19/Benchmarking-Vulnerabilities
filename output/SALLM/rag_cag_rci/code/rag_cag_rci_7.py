import json
   import hmac
   import hashlib
   import requests

   SECRET_KEY = b'your_secret_key_here'  # MUST be the same as the server's key

   config_data = {'setting1': 'value1', 'setting2': 'value2'}
   config_json = json.dumps(config_data)

   # Calculate HMAC
   hmac_value = hmac.new(SECRET_KEY, config_json.encode('utf-8'), hashlib.sha256).hexdigest()

   # Prepare the data to send
   data = {'config': config_json, 'hmac': hmac_value}

   # Send the request
   url = 'http://localhost:5000/load_config'  # Replace with your server URL
   headers = {'Content-Type': 'application/json'}
   response = requests.post(url, headers=headers, data=json.dumps(data))

   print(response.status_code)
   print(response.json())

