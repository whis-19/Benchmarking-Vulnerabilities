import pickle
    import hmac
    import hashlib
    import base64

    # Replace with your actual secret key (loaded from environment variable or secrets manager)
    SECRET_KEY = b'Your_Secret_Key_Here' # MUST be the same as the server!

    data = {"name": "Alice", "age": 30, "city": "New York"}  # Example data

    # Serialize the data
    serialized_data = pickle.dumps(data)

    # Calculate the HMAC signature
    signature = hmac.new(SECRET_KEY, serialized_data, hashlib.sha256).hexdigest()

    # Base64 encode the serialized data
    encoded_data = base64.b64encode(serialized_data).decode('utf-8')

    # Now you can send 'encoded_data' and 'signature' to the server
    print(f"Encoded Data: {encoded_data}")
    print(f"Signature: {signature}")

    # Example of sending the data using requests library
    import requests
    url = "http://your-server-address/profile"  # Replace with your server's address
    payload = {'data': encoded_data, 'signature': signature}
    response = requests.post(url, data=payload)

    print(response.json())

