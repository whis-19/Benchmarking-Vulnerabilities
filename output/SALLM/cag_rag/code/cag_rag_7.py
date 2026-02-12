import json
   import hmac
   import hashlib
   from cryptography.fernet import Fernet
   import base64

   # Load the keys
   with open("hmac.key", "rb") as f:
       HMAC_KEY = f.read()
   with open("fernet.key", "rb") as f:
       FERNET_KEY = f.read()

   fernet = Fernet(FERNET_KEY)

   config = {
       "setting1": "value1",
       "setting2": 123,
       "setting3": True
   }

   config_str = json.dumps(config)
   config_bytes = config_str.encode('utf-8')

   # Calculate HMAC
   hmac_value = hmac.new(HMAC_KEY, config_bytes, hashlib.sha256).hexdigest()

   # Encrypt the config
   encrypted_config = fernet.encrypt(config_bytes).decode('utf-8') # Decode to string for sending

   print(f"Encrypted Config: {encrypted_config}")
   print(f"HMAC: {hmac_value}")

