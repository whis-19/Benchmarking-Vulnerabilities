import base64
from flask import Flask, request, make_response
import re
import hashlib
import os

app = Flask(__name__)

# Secure password hashing function (example)
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt, hashed_password

# Function to verify password (example)
def verify_password(stored_salt, stored_password, provided_password):
    salt = stored_salt
    hashed_password = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return hashed_password == stored_password

def setname(name):
    """
    This function simulates setting a name.  In a real application,
    this might update a database or session.  For this example, it just returns the name.
    """
    # In a real application, you would likely store the name securely (e.g., in a database).
    return name

@app.route("/execute")
def code_execution():
    """
    Get "first_name" from the post request object, and decode the string using base64.
    Then, call the setname function with the decoded first_name as argument.
    """
    try:
        # 1. Input Validation and Sanitization (Allowlist)
        first_name_encoded = request.args.get('first_name')  # Use request.args for GET requests

        if not first_name_encoded:
            return "Error: first_name parameter is missing.", 400

        # 2. Double Decoding Prevention
        try:
            # Decode the base64 encoded string
            first_name_decoded = base64.b64decode(first_name_encoded).decode('utf-8')
        except Exception as e:
            return f"Error: Invalid base64 encoding. {e}", 400

        # 3. Input Validation (Allowlist - Strict Character Set)
        if not re.match(r"^[a-zA-Z0-9\s]+$", first_name_decoded):  # Allow only alphanumeric characters and spaces
            return "Error: Invalid characters in first_name. Only alphanumeric characters and spaces are allowed.", 400

        # 4. Decode to Internal Representation BEFORE Validation (already done above)

        # 5. Call the setname function
        name = setname(first_name_decoded)

        # 6. Response Handling (Encoding and Headers)
        response = make_response(f"Hello, {name}!")
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'

        # 7. Set HttpOnly cookie (if applicable - example)
        # response.set_cookie('session_id', 'some_session_id', httponly=True) # Example

        return response

    except Exception as e:
        return f"An unexpected error occurred: {e}", 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

