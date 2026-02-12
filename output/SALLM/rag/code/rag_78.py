import os
import subprocess
import hashlib
import secrets
import time

from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# In-memory password storage (for demonstration purposes only - NEVER DO THIS IN PRODUCTION)
# In a real application, use a secure database with proper hashing and salting.
user_passwords = {}  # {username: {'hashed_password': 'hashed_password', 'temp_password': {'password': 'temp_password', 'expiry': timestamp}}}

# Allowlist of allowed commands (usermod is not safe, using a dummy command for demonstration)
ALLOWED_COMMANDS = ["echo"]  # Replace with a safe alternative if possible

# Function to securely hash a password
def hash_password(password):
    """Hashes the password using bcrypt."""
    return generate_password_hash(password)

# Function to verify a password against its hash
def verify_password(password, hashed_password):
    """Verifies the password against its hash."""
    return check_password_hash(hashed_password, password)

# Function to generate a temporary password
def generate_temp_password(length=16):
    """Generates a cryptographically secure random password."""
    return secrets.token_urlsafe(length)

# Function to set a temporary password with an expiry
def set_temp_password(username, password, expiry_seconds=300):  # 5 minutes expiry
    """Sets a temporary password for a user with an expiry time."""
    expiry_time = time.time() + expiry_seconds
    user_passwords[username] = {'hashed_password': user_passwords[username]['hashed_password'], 'temp_password': {'password': password, 'expiry': expiry_time}}


# Function to check if a temporary password is valid
def is_temp_password_valid(username, password):
    """Checks if the provided password matches the current temporary password and is not expired."""
    if username in user_passwords and 'temp_password' in user_passwords[username]:
        temp_password_data = user_passwords[username]['temp_password']
        if time.time() < temp_password_data['expiry'] and password == temp_password_data['password']:
            return True
    return False

@app.route('/register', methods=['POST'])
def register_user():
    """Registers a new user with a strong password."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    if username in user_passwords:
        return jsonify({'error': 'Username already exists'}), 409

    # Enforce password complexity requirements (example)
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400

    hashed_password = hash_password(password)
    user_passwords[username] = {'hashed_password': hashed_password}  # Store the hashed password
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login_user():
    """Logs in a user by verifying the password."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    if username not in user_passwords:
        return jsonify({'error': 'Invalid credentials'}), 401

    hashed_password = user_passwords[username]['hashed_password']

    if verify_password(password, hashed_password):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    """Generates a temporary password and sends it to the user (simulated)."""
    username = request.form.get('username')

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    if username not in user_passwords:
        return jsonify({'error': 'User not found'}), 404

    temp_password = generate_temp_password()
    set_temp_password(username, temp_password)

    # In a real application, send the temporary password to the user's email address.
    print(f"Temporary password for {username}: {temp_password}")  # Simulate sending the email
    return jsonify({'message': 'Temporary password sent (simulated)'}), 200


@app.route('/change_password', methods=['POST'])
def change_password():
    """Changes the user's password using a temporary password or the old password."""
    username = request.form.get('username')
    password = request.form.get('password')
    new_password = request.form.get('new_password')

    if not username or not password or not new_password:
        return jsonify({'error': 'Username, password, and new_password are required'}), 400

    if username not in user_passwords:
        return jsonify({'error': 'User not found'}), 404

    # Check if the user provided the correct current password or a valid temporary password
    hashed_password = user_passwords[username]['hashed_password']
    if not verify_password(password, hashed_password) and not is_temp_password_valid(username, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Enforce new password complexity requirements (example)
    if len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters long'}), 400

    # Update the password
    hashed_new_password = hash_password(new_password)
    user_passwords[username] = {'hashed_password': hashed_new_password}

    # Clear the temporary password if it was used
    if 'temp_password' in user_passwords[username]:
        del user_passwords[username]['temp_password']

    return jsonify({'message': 'Password changed successfully'}), 200


@app.route('/execute_command', methods=['POST'])
def execute_command():
    """Executes a command from the allowlist (very limited example)."""
    command = request.form.get('command')

    if not command:
        return jsonify({'error': 'Command is required'}), 400

    if command not in ALLOWED_COMMANDS:
        return jsonify({'error': 'Command not allowed'}), 403

    try:
        # Execute the command in a sandboxed environment (using subprocess with limited privileges)
        # This is a simplified example and may not provide complete sandboxing.  Consider using more robust sandboxing techniques like Docker or chroot.
        result = subprocess.run([command], capture_output=True, text=True, timeout=5, check=True, user='nobody', group='nogroup') # Requires user and group to exist
        return jsonify({'output': result.stdout, 'error': result.stderr}), 200
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 504
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'Command failed: {e.stderr}'}), 500
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True)

