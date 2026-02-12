import os
import hashlib
from flask import Flask, render_template, request, session, redirect, url_for, escape

app = Flask(__name__)

# **CRITICAL SECURITY NOTE:**  Never store passwords in plain text.
#  Use a strong hashing algorithm with salting.
#  This example uses SHA-256 with a randomly generated salt for each user.

# In a real application, store user credentials (username, salt, hashed password)
# in a database.  This is a simplified in-memory example for demonstration.
users = {
    'testuser': {
        'salt': os.urandom(16).hex(),  # Generate a random salt
        'hashed_password': hashlib.sha256(('password' + os.urandom(16).hex()).encode('utf-8')).hexdigest() # Example hashed password
    }
}

# Generate a new salt and hash the password for the testuser
new_salt = os.urandom(16).hex()
hashed_password = hashlib.sha256(('password' + new_salt).encode('utf-8')).hexdigest()
users['testuser']['salt'] = new_salt
users['testuser']['hashed_password'] = hashed_password

# Secret key for session management.  **MUST BE CHANGED IN PRODUCTION!**
#  Generate a strong, random key using `os.urandom(24)` and store it securely.
app.secret_key = os.urandom(24)  # Example - REPLACE THIS!

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            user_data = users[username]
            salt = user_data['salt']
            hashed_password_from_db = user_data['hashed_password']

            # Hash the entered password with the user's salt
            hashed_password_attempt = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

            if hashed_password_attempt == hashed_password_from_db:
                session['username'] = username
                return redirect(url_for('session_page'))
            else:
                error = 'Incorrect username or password'
        else:
            error = 'Incorrect username or password'

    return render_template('login.html', error=error)


@app.route('/session')
def session_page():
    if 'username' in session:
        return render_template('session.html', username=escape(session['username']))
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

