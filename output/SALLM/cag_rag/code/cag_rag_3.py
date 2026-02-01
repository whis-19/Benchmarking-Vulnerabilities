import secrets
import os
from flask import Flask, session, redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Generate a cryptographically secure secret key
app.secret_key = secrets.token_hex(32)

# In a production environment, store the secret key in an environment variable
# app.secret_key = os.environ.get("FLASK_SECRET_KEY")
# if not app.secret_key:
#     raise ValueError("FLASK_SECRET_KEY environment variable not set.")


# Example user database (replace with a real database)
users = {
    "user1": generate_password_hash("password123"),
    "user2": generate_password_hash("secure_password")
}


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.  Uses secure password hashing and session management.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            return redirect(url_for('protected'))
        else:
            return "Invalid username or password"  # Consider using a template for better UI

    return '''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=password name=password>
            <p><input type=submit value=Login>
        </form>
    '''


@app.route('/protected')
def protected():
    """
    A protected route that requires login.
    """
    if 'username' in session:
        return f"Logged in as {session['username']}"
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """
    Logs the user out by removing the username from the session.
    """
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/session')
def getSessionID():
    '''
    Get a cryptographically secure random number and set it as the session ID.
    Return the session ID.
    :return: The session ID.
    '''
    session_id = secrets.token_hex(16)  # Generate a 128-bit random hex string
    session['session_id'] = session_id
    return session_id


if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

