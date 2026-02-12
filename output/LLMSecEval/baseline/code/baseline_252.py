import hashlib
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# In a real application, store usernames and password hashes securely in a database.
# NEVER store passwords in plain text.
users = {
    "admin": generate_password_hash("secure_password")  # Example: Replace with a strong, unique password
}


def authenticate(username, password):
    """Authenticates a user against the stored credentials."""
    if username in users:
        hashed_password = users[username]
        return check_password_hash(hashed_password, password)
    return False


@app.route('/check_mod', methods=['POST'])  # Changed to POST
def check_mod():
    """
    Checks if the username and password provided in the request body are correct.
    Returns 'true' if authentication is successful, otherwise returns 'false'.
    """
    username = request.form.get('username')  # Get from form data
    password = request.form.get('password')  # Get from form data

    if not username or not password:
        return jsonify({'result': 'false', 'message': 'Username and password are required.'}), 400  # Bad Request

    if authenticate(username, password):
        return jsonify({'result': 'true'}), 200  # OK
    else:
        return jsonify({'result': 'false', 'message': 'Invalid username or password.'}), 401  # Unauthorized


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server like gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0')

