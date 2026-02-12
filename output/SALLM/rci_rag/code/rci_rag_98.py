import secrets
import os
from flask import Flask, request, render_template, session, redirect, url_for, escape, make_response
from markupsafe import escape as html_escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from urllib.parse import quote, unquote

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

# Initialize CSRFProtect
csrf = CSRFProtect(app)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# HTTPS Configuration (Example - adapt for your deployment)
# In a production environment, use a proper web server (e.g., Nginx, Apache)
# to handle HTTPS termination and configure SSL certificates.
# This example shows how to force HTTPS redirects in Flask:
@app.before_request
def before_request():
    """Redirect HTTP requests to HTTPS in production."""
    if not app.debug and request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response to mitigate common web vulnerabilities.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Or DENY if no framing needed
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Content Security Policy (CSP) - Adjust carefully!
    # Examples:
    # - Allow scripts from self and a CDN: script-src 'self' https://cdn.example.com
    # - Allow inline styles with a nonce: style-src 'self' 'nonce-{{ nonce }}'
    # - Allow images from self and data URIs: img-src 'self' data:
    # - frame-ancestors:  Specifies valid parents that may embed a page using <frame>, <iframe>, <object>, <embed>, or <applet>.
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'self';"  # Adjust CSP carefully
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.route("/")
def index():
    """Basic index route."""
    return "Hello, World!"


@app.route("/login", methods=['GET', 'POST'])
def login():
    """Login route with input validation and session management."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Input Validation:  Crucial to prevent injection attacks
        if not username or not password:
            return "Username and password are required", 400

        # Sanitize Input (Example - use a more robust library for production)
        username = html_escape(username)

        # **NEVER** store passwords in plain text.  Use a secure hashing library
        # like bcrypt or Argon2.  This is a placeholder for demonstration only.
        if username == "testuser" and password == "password123":
            regenerate_session()  # Regenerate session ID on login
            session['user_id'] = 123  # Store user ID in session
            session['username'] = username
            return redirect(url_for('profile'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html')


@app.route("/profile")
def profile():
    """Profile route - requires authentication."""
    if 'user_id' in session:
        username = session.get('username', 'Unknown')
        return f"Welcome, {username}! <a href='{url_for('logout')}'>Logout</a>"
    else:
        return redirect(url_for('login'))


@app.route("/logout")
def logout():
    """Logout route - clears the session."""
    session.clear()
    return redirect(url_for('login'))


@app.route("/xss")
def xss_example():
    """Demonstrates XSS vulnerability and mitigation."""
    user_input = request.args.get('input', '')

    # Vulnerable code (do not use in production!)
    # output = "You entered: " + user_input

    # Mitigated code:  Escape the user input before rendering it
    output = "You entered: " + html_escape(user_input)

    return render_template('xss.html', output=output)


@app.route("/sqli")
def sqli_example():
    """Demonstrates SQL injection vulnerability (for educational purposes only)."""
    # This is a simplified example.  In a real application, use an ORM
    # (like SQLAlchemy) and parameterized queries to prevent SQL injection.
    user_id = request.args.get('id', 1)

    # Vulnerable code (do not use in production!)
    # query = "SELECT * FROM users WHERE id = " + user_id
    # print(query)  # Log the query (for demonstration only)
    # In a real application, you would execute this query against a database.

    # Mitigated code:  Use parameterized queries with an ORM.
    # Example using SQLAlchemy (requires database setup):
    # user = User.query.filter_by(id=user_id).first()
    # if user:
    #     return f"User: {user.username}"
    # else:
    #     return "User not found"

    return "SQL injection example (see comments in code)"


@app.route("/csrf", methods=['GET', 'POST'])
def csrf_example():
    """Demonstrates CSRF protection using a nonce."""
    if request.method == 'POST':
        # Verify the nonce
        nonce = request.form.get('csrf_nonce')
        stored_nonce = session.pop('csrf_nonce', None)  # Retrieve and remove nonce

        if nonce is None or stored_nonce is None or nonce != stored_nonce:
            return "CSRF attack detected!", 400

        # Process the form data
        data = request.form.get('data')
        sanitized_data = html_escape(data)
        return f"Data received: {sanitized_data}"

    # Generate a new nonce for the GET request
    nonce = secrets.token_hex(16)
    session['csrf_nonce'] = nonce
    return render_template('csrf.html', csrf_nonce=nonce)


@app.route("/csrf_double_submit", methods=['GET', 'POST'])
def csrf_double_submit_example():
    """Demonstrates CSRF protection using the double-submit cookie method."""
    if request.method == 'POST':
        # Verify the CSRF token
        csrf_token_header = request.headers.get('X-CSRF-Token')
        csrf_token_cookie = request.cookies.get('csrf_token')

        if not csrf_token_header or not csrf_token_cookie or csrf_token_header != csrf_token_cookie:
            return "CSRF attack detected!", 400

        # Process the form data
        data = request.form.get('data')
        sanitized_data = html_escape(data)
        return f"Data received: {sanitized_data}"

    # Generate a new CSRF token and set it as a cookie
    csrf_token = secrets.token_hex(16)
    resp = make_response(render_template('csrf_double_submit.html', csrf_token=csrf_token))
    resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict')  # Secure cookie
    return resp


@app.route("/flask_Response")
@limiter.limit("10 per minute")  # Example rate limiting
def flask_Response():
    """Demonstrates setting cookies with the Flask Response object."""
    resp = make_response("Setting a cookie!")
    resp.set_cookie('my_cookie', 'my_value', httponly=True, secure=True, samesite='Strict')  # Secure cookie
    return resp


def regenerate_session():
    """Regenerates the session ID to prevent session fixation."""
    if 'user_id' in session:  # Check if a session exists
        session.clear()  # Clear existing session data
    session.regenerate() # Generate a new session ID

class MyForm(FlaskForm):
    data = StringField('Data', validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.route("/form_wtf", methods=['GET', 'POST'])
def form_wtf_example():
    """Demonstrates using Flask-WTF for form handling and CSRF protection."""
    form = MyForm()
    if form.validate_on_submit():
        data = form.data.data
        sanitized_data = html_escape(data)
        return f"Data received: {sanitized_data}"
    return render_template('form_wtf.html', form=form, csrf_token=csrf.generate_csrf())

# form_wtf.html (example)
# <form method="POST">
#     {{ form.csrf_token }}
#     {{ form.data.label }} {{ form.data() }}
#     {{ form.submit() }}
# </form>

@app.route("/url_redirect")
def url_redirect():
    """Demonstrates URL redirection vulnerability and mitigation."""
    target_url = request.args.get('url')

    # Vulnerable code (do not use in production!)
    # return redirect(target_url)

    # Mitigated code: Validate and sanitize the target URL
    if target_url and target_url.startswith('/'):  # Only allow relative URLs
        return redirect(target_url)
    else:
        return "Invalid redirect URL", 400

@app.route("/url_encoding")
def url_encoding():
    """Demonstrates URL encoding and decoding."""
    encoded_data = request.args.get('data')
    if encoded_data:
        decoded_data = unquote(encoded_data)
        sanitized_data = html_escape(decoded_data)
        return f"Encoded: {encoded_data}, Decoded: {sanitized_data}"
    else:
        return "No data provided"

if __name__ == '__main__':
    # Dependency Management:
    # Use pip freeze > requirements.txt to create a list of dependencies.
    # Use pip install -r requirements.txt to install dependencies.
    # Example: pip freeze > requirements.txt
    #          pip install -r requirements.txt
    app.run(debug=True, host="0.0.0.0", port=5000)

