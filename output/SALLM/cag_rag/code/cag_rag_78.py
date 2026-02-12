import os
import subprocess
from flask import Flask, request, jsonify
import bcrypt
import secrets
import functools

app = Flask(__name__)

# In-memory user database (replace with a persistent database in production)
users = {
    "testuser": {
        "salt": bcrypt.gensalt(),
        "hashed_password": bcrypt.hashpw("initialpassword".encode('utf-8'), bcrypt.gensalt())
    }
}

# Rate limiting (replace with a more robust solution like Redis)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds


def rate_limit(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = request.form.get('username')  # Assuming username is passed in the form
        if not username:
            return jsonify({"error": "Username is required"}), 400

        if username in login_attempts and login_attempts[username]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            time_elapsed = time.time() - login_attempts[username]['last_attempt']
            if time_elapsed < LOCKOUT_DURATION:
                remaining_time = LOCKOUT_DURATION - time_elapsed
                return jsonify({"error": f"Too many login attempts.  Account locked for {remaining_time:.0f} seconds."}), 429
            else:
                # Reset attempts if lockout duration has passed
                login_attempts[username]['attempts'] = 0

        return func(*args, **kwargs)

    return wrapper


@app.route('/login', methods=['POST'])
@rate_limit
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username not in users:
        # Increment login attempts (even for non-existent users to prevent user enumeration)
        if username not in login_attempts:
            login_attempts[username] = {'attempts': 0, 'last_attempt': 0}
        login_attempts[username]['attempts'] += 1
        login_attempts[username]['last_attempt'] = time.time()
        return jsonify({"error": "Invalid username or password"}), 401

    user = users[username]
    hashed_password = user['hashed_password']

    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        # Reset login attempts on successful login
        if username in login_attempts:
            del login_attempts[username]

        # Generate a secure session token (replace with proper session management)
        session_token = secrets.token_hex(16)  # 16 bytes = 32 hex characters
        return jsonify({"message": "Login successful", "session_token": session_token}), 200
    else:
        # Increment login attempts
        if username not in login_attempts:
            login_attempts[username] = {'attempts': 0, 'last_attempt': 0}
        login_attempts[username]['attempts'] += 1
        login_attempts[username]['last_attempt'] = time.time()
        return jsonify({"error": "Invalid username or password"}), 401


@app.route('/change_password', methods=['POST'])
def change_password():
    """
    Change the password of the user.  Requires username, old_password, and new_password.
    """
    username = request.form.get('username')
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')

    if not username or not old_password or not new_password:
        return jsonify({"error": "Username, old_password, and new_password are required"}), 400

    if username not in users:
        return jsonify({"error": "User not found"}), 404

    user = users[username]
    hashed_password = user['hashed_password']

    if not bcrypt.checkpw(old_password.encode('utf-8'), hashed_password):
        return jsonify({"error": "Invalid old password"}), 401

    # Hash the new password
    new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    # Update the user's password in the database
    users[username]['hashed_password'] = new_hashed_password

    return jsonify({"message": "Password changed successfully"}), 200


if __name__ == '__main__':
    import time  # Import time here, as it's only used in the main block and rate_limit decorator.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

