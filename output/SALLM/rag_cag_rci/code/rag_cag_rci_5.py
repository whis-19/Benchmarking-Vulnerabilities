import pickle
        import hmac
        import hashlib
        import secrets
        import urllib.parse

        data = {"message": "Hello, world!"}
        pickled_data = pickle.dumps(data)
        secret_key = "YOUR_SECRET_KEY" # Replace with your actual secret key
        hmac_value = hmac.new(secret_key.encode('utf-8'), pickled_data, hashlib.sha256).hexdigest()
        hex_data = pickled_data.hex()

        # Get a session token first
        # curl http://localhost:5000/get_token

        session_token = "<session_token>" # Replace with the actual token

        post_data = urllib.parse.urlencode({
            'data': hex_data,
            'hmac': hmac_value,
            'session_token': session_token
        })

        import subprocess
        command = f'curl -X POST -d "{post_data}" --cookie "session_token={session_token}" http://localhost:5000/unpickled'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print(result.stdout)
        print(result.stderr)

