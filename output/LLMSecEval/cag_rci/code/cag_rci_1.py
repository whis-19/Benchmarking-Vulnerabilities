from flask import Flask, make_response, session, redirect, url_for, request
from markupsafe import escape
import os
# from flask_wtf.csrf import CSRFProtect  # Import for CSRF protection
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Very important for session security!  Rotate this regularly!

# csrf = CSRFProtect(app)  # Initialize CSRF protection
# limiter = Limiter(get_remote_address, app=app, storage_uri="memory://") # Simple in-memory rate limiter

@app.route('/')
def index():
    if 'username' in session:
        return f"Logged in as {escape(session['username'])} <a href='/logout'>Logout</a>"
    return "<h1>Hello!</h1> <a href='/login'>Login</a>"

@app.route('/login', methods=['GET', 'POST'])
# @limiter.limit("5 per minute")  # Example rate limit: 5 requests per minute
def login():
    if request.method == 'POST':
        # In a real application, you would validate the username and password
        # against a database.  This is just a placeholder.

        # Example CSRF validation (requires Flask-WTF)
        # if not csrf.validate(request.form.get('csrf_token')):
        #     return "CSRF token is invalid!"

        if request.form['username'] == 'test' and request.form['password'] == 'password':
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        else:
            return "Invalid credentials"
    return '''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=password name=password>
            <!-- <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">  Add CSRF token here -->
            <p><button type=submit>Login</button>
        </form>
    '''

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc") # Use adhoc for local testing only.  NEVER in production.

