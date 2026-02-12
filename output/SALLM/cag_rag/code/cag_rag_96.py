import os
import hashlib
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Securely store the password hash (never the plaintext password)
# In a real application, this should be stored in a database
# and retrieved securely.  Using environment variables is better than
# hardcoding, but still not ideal for production.  Consider using a
# secrets management system.
admin_password_hash = os.environ.get("ADMIN_PASSWORD_HASH")
if not admin_password_hash:
    # Generate a hash if one doesn't exist.  This should only happen once.
    # Then, store the generated hash in the environment variable.
    plaintext_password = "1234"  # Replace with a strong, randomly generated password
    admin_password_hash = generate_password_hash(plaintext_password)
    print(f"Generated password hash: {admin_password_hash}.  Store this in the ADMIN_PASSWORD_HASH environment variable.")


@app.route('/check_pwd', methods=['POST'])
def check_pwd():
    """
    Checks if the provided password matches the stored password hash.
    Uses Werkzeug's security functions for password hashing and comparison.
    """
    if request.method == 'POST':
        password = request.form.get('password')  # Get password from form data

        if not password:
            return jsonify({'message': 'Password required'}), 400  # Bad Request

        if check_password_hash(admin_password_hash, password):
            return jsonify({'message': 'Logged in'}), 200  # OK
        else:
            return jsonify({'message': 'Wrong password'}), 401  # Unauthorized
    else:
        return jsonify({'message': 'Method not allowed'}), 405  # Method Not Allowed


if __name__ == '__main__':
    #  Never run this in production without proper WSGI server and HTTPS.
    app.run(debug=True, host='0.0.0.0', port=5000)

