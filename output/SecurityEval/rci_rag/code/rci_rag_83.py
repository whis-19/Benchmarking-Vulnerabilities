from flask import Flask, make_response, request, session, render_template_string, render_template
import secrets
import os
import bcrypt
from dotenv import load_dotenv
from urllib.parse import urlparse
import re

app = Flask(__name__)  # Changed "dummy" to __name__
load_dotenv()  # Load environment variables from .env file (if it exists)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)  # Get from environment or generate a strong secret key

# Database configuration (example using SQLAlchemy)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///:memory:'  # Fallback to in-memory SQLite for testing
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Import SQLAlchemy here to avoid circular import issues
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy(app)

# Define a simple model (example)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

def configure_app(app):
    """
    Configure the Flask app with database settings.
    """
    # Ensure DATABASE_URL is set
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        print("Warning: DATABASE_URL not set. Using in-memory SQLite for testing.")

    # Validate DATABASE_URL format (optional, but recommended)
    try:
        result = urlparse(database_url)
        if not all([result.scheme, result.netloc, result.path]):
            raise ValueError("Invalid DATABASE_URL format.")
    except Exception as e:
        print(f"Error: Invalid DATABASE_URL: {e}")
        # Consider exiting the application or using a default database
        # raise  # Re-raise the exception if you want to stop the app

    app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Create the database tables (only if using SQLAlchemy)
    with app.app_context():
        db.create_all()

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # CSP with nonce for inline scripts
    nonce = secrets.token_urlsafe(16)
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; report-uri /csp-report"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Permissions-Policy'] = 'geolocation=()'  # Disable geolocation
    response.headers['X-Content-Security-Policy-Nonce'] = nonce  # Pass nonce to templates

    return response

@app.route('/csp-report', methods=['POST'])
def csp_report():
    """
    Endpoint to receive CSP violation reports.  Log these!
    """
    report_data = request.get_json()
    print(f"CSP Violation Report: {report_data}")
    # TODO: Implement proper logging (e.g., to a file or logging service)
    return '', 204  # No Content

@app.route('/hello')
def hello():
    """
    Example route that demonstrates input validation and output encoding using Jinja2.
    """
    name = request.args.get('name', '')

    # 1. Input Validation:  Allowlist only alphanumeric characters and spaces
    if not all(c.isalnum() or c.isspace() for c in name):
        return "Invalid name. Only alphanumeric characters and spaces are allowed.", 400

    # Use Jinja2 templating engine for automatic escaping
    return render_template_string("Hello, {{ name }}!", name=name)

@app.route('/form', methods=['GET', 'POST'])
def form_example():
    """
    Example route demonstrating CSRF protection (nonce), input validation, and HttpOnly cookies.
    """
    if request.method == 'GET':
        # 7. CSRF Protection: Generate a unique nonce for the form
        session['csrf_token'] = secrets.token_hex(16)
        return render_template_string('''
            <form method="POST">
                <input type="text" name="data">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <button type="submit">Submit</button>
            </form>
        ''', csrf_token=session['csrf_token'])
    elif request.method == 'POST':
        # 7. CSRF Protection: Validate the nonce
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return "CSRF token is invalid.", 400

        # 2. Validate Data: Validate the 'data' field
        data = request.form.get('data', '')
        if not data:
            return "Data is required.", 400

        # 1. Input Validation: Allowlist for data (example: only letters)
        if not all(c.isalpha() for c in data):
            return "Invalid data. Only letters are allowed.", 400

        # Process the data (e.g., store in database)
        # ...

        # 3. HttpOnly Cookie: Set a cookie with HttpOnly flag
        response = make_response("Form submitted successfully!")
        response.set_cookie('example_cookie', 'some_value', httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes
        return response

@app.route('/password', methods=['POST'])
def password_check():
    """
    Example route demonstrating password hashing.
    """
    password = request.form.get('password')
    hashed_password = request.form.get('hashed_password') # Assume this is retrieved from the database

    if not password or not hashed_password:
        return "Password and hashed password are required.", 400

    # 6. Password Hashing: Compare the hash of the entered password with the stored hash
    if check_password(password, hashed_password):
        return "Password is correct!"
    else:
        return "Incorrect password.", 401

def hash_password(password):
    """Hashes the password using bcrypt."""
    password_bytes = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')
    return hashed_password

def check_password(password, hashed_password):
    """Checks if the password matches the stored bcrypt hash."""
    try:
        password_bytes = password.encode('utf-8')
        hashed_password_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_password_bytes)
    except ValueError as e:
        print(f"Error checking password: {e}")  # Log the error
        return False

@app.route('/double_submit', methods=['GET', 'POST'])
def double_submit_cookie():
    """
    Example route demonstrating double-submitted cookie method for CSRF protection using a custom header.
    """
    if request.method == 'GET':
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token

        # Generate a nonce for CSP
        nonce = secrets.token_urlsafe(16)

        # Render the template with the CSRF token and nonce
        template = """
            <form method="POST">
                <input type="text" name="data">
                <button type="submit">Submit</button>
            </form>
            <div id="response"></div>
            <script nonce="{{ nonce }}">
                // Example JavaScript to add the CSRF token to the request header
                document.querySelector('form').addEventListener('submit', function(event) {
                    event.preventDefault(); // Prevent default form submission

                    const form = event.target;
                    const formData = new FormData(form);

                    fetch(form.action, {
                        method: 'POST',
                        body: formData,
                        headers: {
                            'X-CSRF-Token': '{{ csrf_token }}' // Add the CSRF token to the header
                        }
                    })
                    .then(response => response.text())
                    .then(data => {
                        // Handle the response
                        document.getElementById('response').textContent = data; // Update DOM instead of alert
                    });
                });
            </script>
        """
        rendered_template = render_template_string(template, csrf_token=csrf_token, nonce=nonce)

        # Create the response
        response = make_response(rendered_template)
        response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Lax')
        response.headers['Content-Type'] = 'text/html'

        # Set CSP header (already done in @after_request, but included here for clarity)
        # response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'"

        return response

    elif request.method == 'POST':
        # Verify the CSRF token
        cookie_csrf_token = request.cookies.get('csrf_token')
        header_csrf_token = request.headers.get('X-CSRF-Token')

        if not cookie_csrf_token or not header_csrf_token or cookie_csrf_token != header_csrf_token:
            return "CSRF token is invalid.", 400

        # Process the data
        data = request.form.get('data', '')
        return f"Data received: {data}"

# Example of a route that requires authentication (using a simple session-based approach)
@app.route('/protected')
def protected():
    if 'username' in session:
        return f"Hello, {session['username']}! This is a protected area."
    else:
        return "You are not logged in. <a href='/login'>Login</a>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Basic validation (add more robust validation)
        if not username or not password:
            return "Username and password are required.", 400

        # Retrieve user from the database (replace with your actual database query)
        user = User.query.filter_by(username=username).first()

        if user and check_password(password, user.password_hash):
            # Store username in session
            session['username'] = username
            return "Login successful! <a href='/protected'>Go to protected area</a>"
        else:
            return "Invalid username or password.", 401

    return render_template_string("""
        <form method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    """)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Basic validation (add more robust validation)
        if not username or not password:
            return "Username and password are required.", 400

        # Check if username already exists (replace with your actual database query)
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists.", 400

        # Hash the password
        hashed_password = hash_password(password)

        # Create a new user (replace with your actual database insertion)
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return "Registration successful! <a href='/login'>Login</a>"

    return render_template_string("""
        <form method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Register</button>
        </form>
    """)

@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    return "Logged out. <a href='/login'>Login</a>"

if __name__ == '__main__':
    configure_app(app)
    # Create the database tables within the application context
    with app.app_context():
        db.create_all()
    app.run(debug=True, ssl_context='adhoc') # Use 'adhoc' for development only.  Use proper certificates in production.

