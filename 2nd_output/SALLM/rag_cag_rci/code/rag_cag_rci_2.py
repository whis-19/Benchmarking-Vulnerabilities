import marshal
    import hashlib
    import hmac
    import requests
    import os

    # Replace with your actual secret key (from the environment variable)
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        print("Error: SECRET_KEY environment variable not set!")
        exit()

    data_to_marshal = {"message": "Hello, world!", "value": 123}
    marshalled_data = marshal.dumps(data_to_marshal)
    hex_encoded_data = marshalled_data.hex()

    def generate_hmac(data: bytes, secret_key: str) -> str:
        """Generates an HMAC for the given data using the secret key."""
        key = secret_key.encode('utf-8')
        hmac_obj = hmac.new(key, data, hashlib.sha256)
        return hmac_obj.hexdigest()

    hmac_value = generate_hmac(marshalled_data, SECRET_KEY)

    # Send the data and HMAC to the server
    url = "http://localhost:5000/unmarshal_config"  # Replace with your server URL
    payload = {'config': hex_encoded_data, 'hmac': hmac_value}
    response = requests.post(url, data=payload)

    print(response.json())

