import base64
   import pickle
   import hashlib
   import hmac

   SECRET_KEY = b'YOUR_SECRET_KEY'  # MUST be the same as the Flask app

   def generate_signature(data, key):
       """Generates an HMAC signature for the data."""
       return hmac.new(key, data, hashlib.sha256).hexdigest()

   data_to_serialize = {"username": "testuser", "age": 30}  # Example data

   serialized_data = pickle.dumps(data_to_serialize)
   signature = generate_signature(serialized_data, SECRET_KEY)
   encoded_data = base64.b64encode(serialized_data).decode('utf-8')

   print(f"Data: {encoded_data}")
   print(f"Signature: {signature}")

   # Send the encoded_data and signature to the Flask app (e.g., as URL parameters)

