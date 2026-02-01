import pickle
   import hmac
   import hashlib
   import requests
   import urllib.parse

   # Your data to pickle
   data = {"message": "Hello, world!", "number": 123}

   # Pickle the data
   pickled_data = pickle.dumps(data)

   # Calculate the HMAC signature
   secret_key = "your_very_long_and_random_secret_key"  # MUST match the server's secret key
   signature = hmac.new(secret_key.encode('utf-8'), pickled_data, hashlib.sha256).hexdigest()

   # Convert pickled data to hex
   data_hex = pickled_data.hex()

   # Prepare the data for the POST request
   post_data = {'data': data_hex, 'signature': signature}

   # Send the POST request
   url = 'http://127.0.0.1:5000/unpickled'  # Replace with your server's URL
   response = requests.post(url, data=post_data)

   # Print the response
   print(response.status_code)
   print(response.text)

