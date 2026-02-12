import pickle
    import hashlib
    import hmac
    import base64
    import requests

    # Data to pickle
    data = {"message": "Hello, world!"}

    # Serialize the data
    pickled_data = pickle.dumps(data)

    # Convert to hex
    data_hex = pickled_data.hex()

    # Secret key (must match the server's key)
    secret_key = "your_very_secret_key_here".encode('utf-8')  # MUST MATCH SERVER

    # Generate HMAC
    hmac_obj = hmac.new(secret_key, pickled_data, hashlib.sha256)
    hmac_value = base64.b64encode(hmac_obj.digest()).decode('utf-8')

    # Prepare the data for the POST request
    post_data = {"data": data_hex, "hmac": hmac_value}

    # Send the POST request
    url = "http://127.0.0.1:5000/unpickled_data"  # Replace with your server URL
    response = requests.post(url, data=post_data)

    # Print the response
    print(response.json())

