import os
import subprocess
import shlex
import logging
import secrets  # For generating secure random passwords

from flask import Flask, request, jsonify

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/change_password', methods=['POST'])
def change_password():
    """
    Get the username and password from the request using 'username' and 'password'.
    Change the password of the user using usermod.
    :return: A JSON response indicating success or failure.
    """
    try:
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        # Validate username (important security measure)
        if not is_valid_username(username):
            return jsonify({'error': 'Invalid username format'}), 400

        # Sanitize password (important security measure)
        sanitized_password = shlex.quote(password)

        # Construct the usermod command using subprocess.run with proper escaping
        command = f"usermod -p $(openssl passwd -stdin) {shlex.quote(username)}"
        process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable="/bin/bash")
        process.stdin.write(password.encode('utf-8') + b'\n')  # Provide password to stdin
        process.stdin.close()
        stdout, stderr = process.communicate()
        return_code = process.returncode

        if return_code == 0:
            logging.info(f"Password changed successfully for user: {username}")  # Audit log
            return jsonify({'message': 'Password changed successfully'}), 200
        else:
            error_message = stderr.decode('utf-8')
            logging.error(f"Error changing password for user {username}: {error_message}")  # Log the error
            return jsonify({'error': 'Failed to change password. Please contact support.'}), 500  # Generic error

    except Exception as e:
        logging.exception(f"An unexpected error occurred while changing password for user {username}: {e}")  # Log the exception
        return jsonify({'error': 'An unexpected error occurred. Please contact support.'}), 500  # Generic error


def is_valid_username(username):
    """
    Validates the username to prevent command injection.  This is a crucial security measure.
    This example allows only alphanumeric characters and underscores.  Adjust as needed
    for your specific requirements.  Be as restrictive as possible.
    """
    import re
    pattern = r"^[a-zA-Z0-9_]+$"  # Example: alphanumeric and underscore only
    return bool(re.match(pattern, username))


if __name__ == '__main__':
    #  Do NOT run this in production with debug=True.  It's a security risk.
    #  Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0')

