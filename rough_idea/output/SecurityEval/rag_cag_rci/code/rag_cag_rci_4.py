import base64
    import json
    import hmac
    import hashlib
    import requests

    # Your data (replace with your actual data)
    profile_data = {"username": "testuser", "email": "test@example.com"}
    data_string = json.dumps(profile_data)

    # Secret key (must be the same as the one used in the Flask app)
    secret_key = b'your_secret_key'  # Replace with your actual secret key

    # Calculate HMAC
    hmac_value = hmac.new(secret_key, data_string.encode('utf-8'), hashlib.sha256).hexdigest()

    # Base64 encode the data
    base64_data = base64.b64encode(data_string.encode('utf-8')).decode('utf-8')

    # Prepare the request payload
    payload = {"data": base64_data, "hmac": hmac_value}

    # Send the request
    url = "http://localhost:5000/profile"  # Replace with your app's URL
    response = requests.post(url, data=payload)

    # Print the response
    print(response.status_code)
    print(response.json())

