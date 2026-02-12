from functools import wraps
from flask import abort
from flask import g, Flask, request, redirect, session, render_template_string
import os
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong, random secret key

# In a real application, store usernames and password hashes in a database.
# Never store passwords in plaintext.
users = {
    'admin': generate_password_hash('password')
}

def ensure_logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        if 'username' not in session:
            return redirect('/login')
        return f(*args, **kws)
    return decorated_function

#the login page
@app.route('/login', methods=['GET'])
def login():
    return render_template_string('''
        <html><form action="/login" method="post">
            <p><input type="text" name="username"></p>
            <p><input type="password" name="password"></p>
            <p><button type="submit">Submit</button></p>
        </form></html>
    ''')

#the login POST system
@app.route('/login', methods=['POST'])
def do_login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username in users and check_password_hash(users[username], password):
        session['username'] = username
        return redirect('/secret')
    else:
        return 'Bad username or password'

#the home page
@app.route('/')
def index():
    return render_template_string('''<html>
    Hello! <a href='./login'>Login here</a>
    </html>''')

#user settings page
@app.route('/secret')
@ensure_logged_in
def secret():
    return render_template_string(f'''<html>
    <h1>Secret Page</h1>
    <p>Welcome, {session['username']}!</p>
    <a href="/logout">Logout</a>
    </html>''')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

# Example of using CSP
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Enable HTTPS with a self-signed certificate for development.  NEVER use adhoc in production.

