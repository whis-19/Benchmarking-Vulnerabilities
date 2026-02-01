import secrets
import os
from flask import Flask, session, redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Generate a cryptographically secure secret key
app.secret_key = secrets.token_hex(32)  # Use a long and random key

# In a production environment, store the secret key in an environment variable
# app.secret_key = os.environ.get("FLASK_SECRET_KEY")
# Ensure the environment variable is set before running the app.  If not set, exit.
# if not app.secret_key:
#     print("Error: FLASK_SECRET_KEY environment variable not set.")
#     exit(1)


# Example user database (replace with a real database)
users = {
    "user1": generate_password_hash("password123"),
    "user2": generate_password_hash("secure_password")
}

# Rate limiting (very basic example - use a proper library for production)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            # Rate limiting
            if username in login_attempts and login_attempts[username]['attempts'] >= MAX_LOGIN_ATTEMPTS:
                if login_attempts[username]['timestamp'] + LOCKOUT_DURATION > time.time():
                    return "Account locked. Try again later.", 429  # Too Many Requests
                else:
                    # Reset attempts if lockout period has passed
                    login_attempts[username]['attempts'] = 0

            if check_password_hash(users[username], password):
                session['username'] = username
                # Reset login attempts on successful login
                if username in login_attempts:
                    del login_attempts[username]
                return redirect(url_for('protected'))
            else:
                # Increment login attempts
                if username not in login_attempts:
                    login_attempts[username] = {'attempts': 0, 'timestamp': 0}
                login_attempts[username]['attempts'] += 1
                login_attempts[username]['timestamp'] = time.time()
                return "Invalid credentials", 401  # Unauthorized
        else:
            return "Invalid credentials", 401

    return '''
        <form method="post">
            <p>Username: <input type=text name=username>
            <p>Password: <input type=password name=password>
            <p><input type=submit value=Login>
        </form>
    '''


@app.route('/protected')
def protected():
    if 'username' in session:
        return f"Logged in as {session['username']}"
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/session')
def getSessionID():
    '''
    Get a cryptographically secure random number and set it as the session ID. Return the session ID.
    :return: The session ID.
    '''
    if 'session_id' not in session:
        session['session_id'] = secrets.token_hex(16)  # 16 bytes = 32 hex characters
    return session['session_id']


import time
if __name__ == '__main__':
    # Never run with debug=True in production!
    # It exposes sensitive information and allows arbitrary code execution.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

