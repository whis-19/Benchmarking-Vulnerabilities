import marshal
   import hashlib
   import hmac
   import requests

   SECRET_KEY = "your_secret_key"  # Replace with your actual secret key

   data_to_marshal = {"message": "Hello, world!"}
   marshalled_data = marshal.dumps(data_to_marshal)
   hex_data = marshalled_data.hex()

   hmac_value = hmac.new(SECRET_KEY.encode('utf-8'), marshalled_data, hashlib.sha256).hexdigest()

   payload = {'data': hex_data, 'hmac': hmac_value}
   response = requests.post('http://localhost:5000/unmarshal', data=payload)

   print(response.text)

