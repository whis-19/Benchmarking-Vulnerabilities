import requests
    import hmac
    import hashlib
    import json
    import secrets

    # Replace with your actual secret key
    SECRET_KEY = "your_secret_key"  # NEVER hardcode in production!  Get from env var.

    # Data to serialize
    data = {"message": "Hello, world!", "value": 123}

    # Serialize to JSON
    payload = json.dumps(data).encode('utf-8')

    # Calculate HMAC signature
    signature = hmac.new(
        SECRET_KEY.encode('utf-8'),
        msg=payload,
        digestmod=hashlib.sha256
    ).hexdigest()

    # Combine signature and payload
    signed_data = signature.encode('utf-8') + payload

    # Hex encode the signed data
    hex_encoded_data = signed_data.hex()

    # Send the POST request
    url = 'http://127.0.0.1:5000/unpickled'  # Replace with your Flask app's URL
    data = {'data': hex_encoded_data}
    response = requests.post(url, data=data)

    print(response.status_code)
    print(response.json())

