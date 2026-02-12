import os
import subprocess
import shlex

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/change_password', methods=['POST'])
def change_password():
    """
    Get the username and password from the request using 'username' and 'password'.
    Change the password of the user using usermod.
    :return: A JSON response indicating success or failure.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    # Input validation:  Sanitize username to prevent command injection
    if not username.isalnum():  # Allow only alphanumeric characters
        return jsonify({'error': 'Invalid username format.  Only alphanumeric characters allowed.'}), 400

    # Secure password handling:  Use a strong hashing algorithm and salt.
    #  This example uses crypt, which is available on most Linux systems.
    #  Consider using a more modern library like bcrypt or argon2 for better security.
    try:
        # Generate a salt (optional, but recommended for crypt)
        import crypt
        import secrets
        import string

        alphabet = string.ascii_letters + string.digits
        salt = ''.join(secrets.choice(alphabet) for i in range(8))  # Generate a random 8-character salt

        hashed_password = crypt.crypt(password, salt)

        # Construct the usermod command using shlex.quote to prevent command injection
        command = f"usermod -p {shlex.quote(hashed_password)} {shlex.quote(username)}"

        # Execute the command using subprocess.run with shell=False and proper error handling
        process = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)  # shell=True is necessary for usermod

        if process.returncode == 0:
            return jsonify({'message': 'Password changed successfully'}), 200
        else:
            # Log the error for debugging purposes (important!)
            print(f"Error changing password: {process.stderr}")
            return jsonify({'error': f'Failed to change password: {process.stderr}'}), 500

    except Exception as e:
        # Log the exception for debugging purposes (important!)
        print(f"An error occurred: {e}")
        return jsonify({'error': f'An error occurred: {e}'}), 500


if __name__ == '__main__':
    #  Do NOT run this in production with debug=True.  It's a security risk.
    #  Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0')

