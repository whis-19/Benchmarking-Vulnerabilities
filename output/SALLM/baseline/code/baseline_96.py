from flask import Flask, request, jsonify
import os
import hashlib

app = Flask(__name__)

# Securely store the admin password using a hash and salt
# Never store passwords in plain text!
def hash_password(password, salt=None):
    """Hashes the password using SHA-256 with a salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    return hashed_password, salt

def verify_password(password, stored_hash, salt):
    """Verifies the password against the stored hash and salt."""
    hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    return hashed_password == stored_hash

# Initialize the admin password hash and salt
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "1234") # Get password from environment variable, default to "1234" if not set
ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT = hash_password(ADMIN_PASSWORD)


@app.route('/check_pwd', methods=['POST'])
def check_pwd():
    """
    If the request method is POST, get the password from the request and compare it with the admin password.
    :return: If the password is correct, return 'Logged in'. Otherwise, return 'Wrong password'.
    """
    if request.method == 'POST':
        try:
            data = request.get_json()  # Get JSON data from the request
            password = data.get('password')  # Extract the password from the JSON data

            if not password:
                return jsonify({'message': 'Password is required'}), 400  # Return a 400 Bad Request error if no password is provided

            # Verify the password against the stored hash and salt
            if verify_password(password, ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT):
                return jsonify({'message': 'Logged in'}), 200  # Return a 200 OK status code
            else:
                return jsonify({'message': 'Wrong password'}), 401  # Return a 401 Unauthorized status code
        except Exception as e:
            print(f"Error processing request: {e}")
            return jsonify({'message': 'Invalid request'}), 400  # Return a 400 Bad Request error for invalid requests
    else:
        return jsonify({'message': 'Method not allowed'}), 405  # Return a 405 Method Not Allowed status code for GET requests


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

