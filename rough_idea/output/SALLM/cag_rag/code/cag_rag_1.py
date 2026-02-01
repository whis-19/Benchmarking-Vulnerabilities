import marshal
    import hashlib
    import hmac
    import requests
    import os

    # Generate some data to marshal
    data = {"message": "Hello, world!"}
    marshalled_data = marshal.dumps(data)

    # Calculate the HMAC
    SECRET_KEY = b'your_secret_key'  # Replace with the same key used in the Flask app
    calculated_hmac = hmac.new(SECRET_KEY, marshalled_data, hashlib.sha256).hexdigest()

    # Convert the marshalled data to hex
    hex_data = marshalled_data.hex()

    # Prepare the data for the POST request
    post_data = {'data': hex_data, 'hmac': calculated_hmac}

    # Send the POST request
    response = requests.post('http://localhost:5000/unmarshal', data=post_data)

    # Print the response
    print(response.status_code)
    print(response.text)

