import marshal
   import hashlib
   import hmac
   import requests

   SECRET_KEY = "your_very_long_and_random_secret_key"  # MUST match the server's SECRET_KEY

   data_to_send = {"message": "Hello, world!"}  # Example data

   # Marshal the data
   marshalled_data = marshal.dumps(data_to_send)

   # Convert to hex
   config_hex = marshalled_data.hex()

   # Calculate HMAC
   hmac_value = hmac.new(
       SECRET_KEY.encode('utf-8'),
       msg=config_hex.encode('utf-8'),
       digestmod=hashlib.sha256
   ).hexdigest()

   # Create the JSON payload
   payload = {
       "config": config_hex,
       "hmac": hmac_value
   }

   # Send the request
   response = requests.post("http://localhost:5000/unmarshal_config", json=payload)

   print(response.json())

