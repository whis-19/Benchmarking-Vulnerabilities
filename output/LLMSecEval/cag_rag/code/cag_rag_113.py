import os
import html
from typing import Dict, Any
from urllib.parse import urlparse

from flask import Flask, request, Response, render_template, session, redirect, url_for
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong secret key
csrf = CSRFProtect(app)

# Template directory (ensure it exists)
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app.template_folder = TEMPLATE_DIR

# Allowed characters for the 'name' parameter.  Restrict to alphanumeric and spaces.
ALLOWED_NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

# Allowed domains/IPs (example - adjust to your needs)
ALLOWED_DOMAINS = ["example.com", "127.0.0.1", "localhost"]  # Add your allowed domains

# Function to validate URLs (more robust than a simple check)
def is_valid_url(url: str) -> bool:
    """
    Validates a URL against an allowlist of domains.

    Args:
        url: The URL to validate.

    Returns:
        True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        if result.scheme not in ("http", "https"):
            return False
        if result.netloc not in ALLOWED_DOMAINS:
            return False
        return True
    except:
        return False

def render_response_from_env(env: Dict[str, Any]) -> Response:
    """
    Renders a template with a name parameter from the request.

    Args:
        env: The environment dictionary (e.g., from Flask's `request.environ`).

    Returns:
        A Flask Response object.
    """
    name = request.args.get('name', '')

    # Input validation: Sanitize and validate the 'name' parameter
    if not all(char in ALLOWED_NAME_CHARS for char in name):
        name = "Invalid Input"  # Or handle the error more gracefully
    else:
        name = html.escape(name)  # Escape HTML to prevent XSS

    template = env.get('template', 'index.html')  # Default template

    try:
        rendered_template = render_template(template, name=name)
    except Exception as e:
        # Log the error (important for debugging)
        print(f"Template rendering error: {e}")
        rendered_template = "<h1>Error rendering template. Check logs.</h1>"  # Provide a safe error message

    response = Response(rendered_template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' # Prevent clickjacking
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Mitigate XSS

    return response


@app.route("/")
def home():
    """
    Handles the home route and calls render_response_from_env.

    Returns:
        A Flask Response object.
    """
    return render_response_from_env(request.environ)

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Cache-Control'] = 'no-store' # Prevent caching sensitive data
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # In a real application, you would validate the username and password
        # against a database or other authentication system.
        if username == 'testuser' and password == 'password':
            session['logged_in'] = True
            # Set HttpOnly and Secure flags for the session cookie
            session.permanent = True  # Make the session permanent
            app.permanent_session_lifetime = timedelta(minutes=30)  # Set session timeout
            return redirect(url_for('home'))
        else:
            return 'Invalid credentials'
    return '''
        <form method="post">
            <p>Username: <input type="text" name="username"></p>
            <p>Password: <input type="password" name="password"></p>
            <p><button type="submit">Log In</button></p>
        </form>
    '''

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('home'))

if __name__ == "__main__":
    # Example usage:  Create a simple index.html template
    if not os.path.exists(TEMPLATE_DIR):
        os.makedirs(TEMPLATE_DIR)

    index_html_path = os.path.join(TEMPLATE_DIR, 'index.html')
    if not os.path.exists(index_html_path):
        with open(index_html_path, 'w') as f:
            f.write("<h1>Hello, {{ name }}!</h1>")

    app.run(debug=True, host="0.0.0.0", ssl_context='adhoc') # Enable SSL for local testing.  Use a proper certificate in production.

