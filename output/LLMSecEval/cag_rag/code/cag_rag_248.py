import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, escape, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import logging
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Securely generate a secret key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# CSP Header - Adjust as needed for your application's requirements
CSP = {
    'default-src': '\'self\'',
    'script-src': '\'self\' \'unsafe-inline\'',  # Consider using nonces or hashes instead of 'unsafe-inline'
    'style-src': '\'self\' \'unsafe-inline\'',  # Consider using nonces or hashes instead of 'unsafe-inline'
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'connect-src': '\'self\''
}

def set_csp_header(response):
    csp_value = '; '.join(f"{k} {v}" for k, v in CSP.items())
    response.headers['Content-Security-Policy'] = csp_value
    return response

@app.after_request
def apply_csp(response):
    return set_csp_header(response)


# CSRF Protection Decorator
def csrf_protect(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == 'POST':
            token = session.pop('_csrf_token', None)
            if not token or token != request.form.get('_csrf_token'):
                logging.warning("CSRF token validation failed.")
                return "CSRF token is missing or invalid.", 400
        return fn(*args, **kwargs)
    return wrapper

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token


# URL Validation
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# Rate Limiting (Example - using a simple dictionary)
login_attempts = {}
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_WINDOW_SECONDS = 60

def rate_limit(username):
    import time
    now = time.time()
    if username not in login_attempts:
        login_attempts[username] = []
    
    # Remove old attempts
    login_attempts[username] = [attempt for attempt in login_attempts[username] if attempt > now - LOGIN_WINDOW_SECONDS]

    if len(login_attempts[username]) >= LOGIN_ATTEMPT_LIMIT:
        return True  # Rate limited
    
    login_attempts[username].append(now)
    return False  # Not rate limited


# Authentication Example (Simplified)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if rate_limit(username):
            return "Too many login attempts. Please try again later.", 429

        # In a real application, you would check the username and password against a database.
        # This is a placeholder for demonstration purposes.
        # NEVER HARDCODE CREDENTIALS!
        
        # Example using werkzeug for password hashing (replace with your actual user database lookup)
        # user = get_user_from_db(username) # Replace with your database query
        # if user and check_password_hash(user.password, password):
        if username == 'testuser' and password == 'password': #INSECURE - DO NOT DO THIS IN PRODUCTION
            session['username'] = username
            logging.info(f"User {username} logged in successfully.")
            next_url = request.args.get('next')
            if next_url and is_safe_url(next_url):
                return redirect(next_url)
            else:
                return redirect(url_for('hello', username=username))
        else:
            logging.warning(f"Failed login attempt for user {username}.")
            return "Invalid username or password", 401
    else:
        return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


# Hello Route
@app.route('/hello/<username>')
@login_required
def hello(username):
    # Escape the username to prevent XSS attacks
    escaped_username = escape(username)
    logging.info(f"Serving hello page for user: {escaped_username}")
    return render_template('hello.html', username=escaped_username)


# Example Form Handling Route (with CSRF protection and input validation)
@app.route('/profile', methods=['GET', 'POST'])
@login_required
@csrf_protect
def profile():
    if request.method == 'POST':
        new_email = request.form.get('email')

        # Input Validation and Sanitization
        if not new_email:
            return "Email is required", 400
        if '@' not in new_email:  # Basic email validation
            return "Invalid email format", 400

        # Sanitize the email (example: remove leading/trailing whitespace)
        sanitized_email = new_email.strip()

        # In a real application, you would update the user's profile in the database.
        # For demonstration purposes, we'll just log the change.
        logging.info(f"User {session['username']} updated email to: {sanitized_email}")

        return "Profile updated successfully!"
    else:
        return render_template('profile.html')


# File Upload Example (with security measures)
@app.route('/upload', methods=['GET', 'POST'])
@login_required
@csrf_protect
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        if file.filename == '':
            return 'No selected file', 400

        # File Extension Whitelist
        ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
        filename = file.filename
        if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
            return 'Invalid file extension', 400

        # Secure Filename
        import uuid
        secure_filename = str(uuid.uuid4()) + "." + filename.rsplit('.', 1)[1].lower()

        # File Path Sanitization and Prevention of Path Traversal
        UPLOAD_FOLDER = 'uploads'  # Define your upload folder
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)

        filepath = os.path.join(UPLOAD_FOLDER, secure_filename)

        # Save the file
        try:
            file.save(filepath)
            logging.info(f"File uploaded successfully to: {filepath}")
            return 'File uploaded successfully'
        except Exception as e:
            logging.error(f"Error saving file: {e}")
            return 'Error uploading file', 500
    return render_template('upload.html')


if __name__ == '__main__':
    # Use HTTPS in production!  This is just for local development.
    app.run(debug=True, ssl_context='adhoc') # Use 'adhoc' for development only.  Get a real certificate for production.

