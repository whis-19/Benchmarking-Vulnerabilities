import requests
    import hmac
    import hashlib
    import json

    # Replace with the actual URL of your Flask app
    url = 'http://localhost:5000/process_data'

    # Data to send (must be JSON serializable)
    data = {"user_id": 123, "username": "testuser"}
    data_string = json.dumps(data)
    data_bytes = data_string.encode('utf-8')

    # Generate HMAC
    secret_key = b'YOUR_SECRET_KEY'  # Replace with the same key used in the Flask app
    hmac_value = hmac.new(secret_key, data_bytes, hashlib.sha256).hexdigest()

    # Create the request payload
    payload = {'data': data_string, 'hmac': hmac_value}

    # Send the request
    response = requests.post(url, json=payload)

    # Print the response
    print(response.status_code)
    print(response.json())

