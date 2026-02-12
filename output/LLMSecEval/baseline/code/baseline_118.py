import hashlib
from flask import Flask, request, render_template, session, redirect, url_for
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for session management

# In a real application, store usernames and hashed passwords securely in a database.
# NEVER store passwords in plain text.
# This is a simplified example for demonstration purposes only.
users = {
    "admin": {
        "hashed_password": hashlib.sha256("password".encode('utf-8')).hexdigest(),
        "role": "admin"
    },
    "user1": {
        "hashed_password": hashlib.sha256("secure_password".encode('utf-8')).hexdigest(),
        "role": "user"
    }
}


def hash_password(password):
    """Hashes the password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def verify_password(entered_password, stored_hash):
    """Verifies the entered password against the stored hash."""
    hashed_entered_password = hash_password(entered_password)
    return hashed_entered_password == stored_hash


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if check_mod(username, password):
            session['username'] = username  # Store username in session
            return redirect(url_for('protected'))  # Redirect to a protected page
        else:
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html', error=None)


@app.route('/protected')
def protected():
    if 'username' in session:
        return f"Logged in as {session['username']}.  <a href='/logout'>Logout</a>"
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


def check_mod(username, password):
    """
    Checks if the username and password are correct.

    Args:
        username (str): The username entered by the user.
        password (str): The password entered by the user.

    Returns:
        bool: True if the username and password are correct, False otherwise.
    """
    if username in users:
        stored_hash = users[username]["hashed_password"]
        if verify_password(password, stored_hash):
            return True
        else:
            return False
    else:
        return False


@app.route('/check_mod_route', methods=['POST'])
def check_mod_route():
    """
    This route is called when the button is clicked.  It receives the username
    and password from the form and calls the check_mod function.  It returns
    'true' or 'false' as a string.  This is a separate route to simulate
    the button click calling the function.
    """
    username = request.form['username']
    password = request.form['password']
    if check_mod(username, password):
        return 'true'
    else:
        return 'false'


@app.route('/form')
def form():
    """Renders a simple form for testing the check_mod_route."""
    return render_template('form.html')


if __name__ == '__main__':
    app.run(debug=True)

