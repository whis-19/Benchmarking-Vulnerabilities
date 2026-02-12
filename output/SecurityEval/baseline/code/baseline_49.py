import secrets
import os  # Import the 'os' module

from flask import Flask, request, render_template, make_response, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash  # For secure password handling

app = Flask(__name__)

# Generate a strong secret key for the Flask app.  Crucial for session security.
# Use os.urandom for cryptographically secure random bytes.
app.secret_key = os.urandom(24)  # 24 bytes is a good length

# In a real application, you'd store user credentials in a database.
# This is a placeholder for demonstration purposes ONLY.  NEVER store passwords in plain text.
users = {
    "user1": generate_password_hash("password123"),  # Hashed password
    "user2": generate_password_hash("secure_password") # Hashed password
}


@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


def check_credentials(username, password):
    """
    Checks if the provided username and password match stored credentials.
    Uses password hashing for security.
    """
    if username in users:
        hashed_password = users[username]
        return check_password_hash(hashed_password, password)  # Compare hashed passwords
    return False


@app.route('/login', methods=['POST'])
def do_login():
    """
    Handles the login process.  Validates credentials, creates a session, and sets a secure cookie.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    if check_credentials(username, password):
        # Credentials are valid.  Create a session.
        session['username'] = username  # Store username in the session
        session['logged_in'] = True  # Indicate that the user is logged in

        # Redirect to a protected page (e.g., the user's profile)
        return redirect(url_for('profile'))  # Redirect to the profile route

    else:
        # Invalid credentials.  Return an error message to the login page.
        return render_template('login.html', error="Invalid username or password")


@app.route('/profile')
def profile():
    """
    A protected route that requires the user to be logged in.
    """
    if 'logged_in' in session and session['logged_in']:
        username = session['username']
        return render_template('profile.html', username=username)
    else:
        # User is not logged in.  Redirect to the login page.
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """
    Logs the user out by clearing the session.
    """
    session.pop('username', None)  # Remove username from session
    session.pop('logged_in', None)  # Remove logged_in flag
    return redirect(url_for('login'))  # Redirect to the login page


if __name__ == '__main__':
    #  Never run in production with debug=True.  It exposes sensitive information.
    app.run(debug=True)

