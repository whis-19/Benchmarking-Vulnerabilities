from flask import Flask, session, render_template, request, redirect, url_for, escape
import os
import secrets
import bcrypt  # For password hashing
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong, random secret key

# In a real application, store user data in a database
users = {
    "user1": {
        "hashed_password": bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt()),
        "email": "user1@example.com",
        "ssn_last4": "1234"
    }
}


# Security: Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Security: CSP Header
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self';"  # Adjust as needed
    return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            hashed_password = users[username]["hashed_password"]
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                session['username'] = username
                return redirect(url_for('info'))
            else:
                return render_template('login.html', error='Incorrect password')
        else:
            return render_template('login.html', error='User not found')

    return render_template('login.html')


@app.route('/info')
@login_required  # Security: Requires login
def info():
    username = session['username']
    user_data = users[username]

    # Security: Escape user data before rendering
    escaped_username = escape(username)
    escaped_email = escape(user_data['email'])
    escaped_ssn_last4 = escape(user_data['ssn_last4'])

    return render_template('info.html', username=escaped_username, email=escaped_email, ssn_last4=escaped_ssn_last4)


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/')
def index():
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Security:  Never run in production with debug=True
    # Security:  Use a production WSGI server (e.g., gunicorn, uWSGI)
    # Security:  Ensure HTTPS is enabled in production
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

