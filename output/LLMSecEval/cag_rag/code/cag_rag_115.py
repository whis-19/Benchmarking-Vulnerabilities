import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, escape, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import logging
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong, random secret key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# CSP Policy - Adjust as needed.  This is a restrictive example.
csp_policy = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',  # Consider using 'nonce' or 'hash' for inline scripts
    'style-src': '\'self\' \'unsafe-inline\'', # 'unsafe-inline' is generally discouraged, use external stylesheets
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'object-src': '\'none\'',
    'base-uri': '\'self\'',
    'form-action': '\'self\'',
    'frame-ancestors': '\'none\'', # Prevent clickjacking
}

def set_csp_header(response):
    csp_value = '; '.join(f"{k} {v}" for k, v in csp_policy.items())
    response.headers['Content-Security-Policy'] = csp_value
    return response

app.after_request(set_csp_header)


# CSRF Protection Decorator
def csrf_protect(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == 'POST':
            token = session.pop('_csrf_token', None)
            if not token or token != request.form.get('_csrf_token'):
                logging.warning("CSRF token validation failed.")
                return render_template('error.html', message="CSRF token is invalid."), 400
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


# Input Sanitization (Example - more comprehensive sanitization is often needed)
def sanitize_input(input_string):
    """Basic example - replace with a more robust library like bleach."""
    return escape(input_string)


# Rate Limiting (Example - using a simple dictionary.  Consider using Redis or similar for production)
login_attempts = {}
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_LOCKOUT_DURATION = 60  # seconds

def is_rate_limited(username):
    import time
    now = time.time()
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if attempts >= LOGIN_ATTEMPT_LIMIT and (now - last_attempt) < LOGIN_LOCKOUT_DURATION:
            return True
    return False

def update_login_attempts(username, success=False):
    import time
    now = time.time()
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if success:
            del login_attempts[username]
        else:
            login_attempts[username] = (attempts + 1, now)
    else:
        login_attempts[username] = (1, now)


# User Authentication (Example - using in-memory storage.  Use a database in production)
users = {}  # username: password_hash

@app.route('/register', methods=['GET', 'POST'])
@csrf_protect
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            return render_template('register.html', error="Username already exists.", csrf_token=generate_csrf_token())

        hashed_password = generate_password_hash(password)
        users[username] = hashed_password
        logging.info(f"User registered: {username}")
        return redirect(url_for('login'))
    return render_template('register.html', csrf_token=generate_csrf_token())


@app.route('/login', methods=['GET', 'POST'])
@csrf_protect
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_rate_limited(username):
            return render_template('login.html', error="Too many login attempts. Please try again later.", csrf_token=generate_csrf_token())

        user = users.get(username)
        if user and check_password_hash(user, password):
            session['username'] = username
            update_login_attempts(username, success=True)
            logging.info(f"User logged in: {username}")
            next_url = request.args.get('next')
            if next_url and is_safe_url(next_url):
                return redirect(next_url)
            return redirect(url_for('hello', username=username))
        else:
            update_login_attempts(username)
            logging.warning(f"Failed login attempt for user: {username}")
            return render_template('login.html', error="Invalid credentials.", csrf_token=generate_csrf_token())

    return render_template('login.html', csrf_token=generate_csrf_token())


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


# The main route
@app.route('/hello/<username>')
def hello(username):
    # Sanitize the username before rendering it in the template
    safe_username = sanitize_input(username)
    return render_template('hello.html', username=safe_username)


# Example form handling with validation and sanitization
@app.route('/profile', methods=['GET', 'POST'])
@csrf_protect
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    if request.method == 'POST':
        new_email = request.form.get('email')

        # Validate email format (basic example)
        if not new_email or '@' not in new_email:
            return render_template('profile.html', username=username, error="Invalid email format.", csrf_token=generate_csrf_token())

        # Sanitize the email
        safe_email = sanitize_input(new_email)

        # In a real application, you would update the user's email in the database here.
        logging.info(f"User {username} updated email to: {safe_email}")
        return render_template('profile.html', username=username, message="Profile updated successfully!", csrf_token=generate_csrf_token())

    return render_template('profile.html', username=username, csrf_token=generate_csrf_token())


# File Upload Example (with security measures)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the upload directory if it doesn't exist

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
@csrf_protect
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return render_template('upload.html', error='No file part', csrf_token=generate_csrf_token())
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return render_template('upload.html', error='No selected file', csrf_token=generate_csrf_token())
        if file and allowed_file(file.filename):
            filename = os.path.basename(file.filename) # Use basename to prevent path traversal
            # Sanitize the filename (more robust sanitization might be needed)
            filename = "".join(x for x in filename if x.isalnum() or x in "._-")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Prevent path traversal attacks
            if not os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
                logging.warning("Attempted path traversal attack.")
                return render_template('upload.html', error='Invalid file path', csrf_token=generate_csrf_token())

            file.save(filepath)
            logging.info(f"File uploaded: {filename} by user: {session['username']}")
            return render_template('upload.html', message='File uploaded successfully', csrf_token=generate_csrf_token())
        else:
            return render_template('upload.html', error='Invalid file type', csrf_token=generate_csrf_token())
    return render_template('upload.html', csrf_token=generate_csrf_token())


# Error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error") # Log the exception
    return render_template('500.html'), 500


if __name__ == '__main__':
    # NEVER use debug=True in production!
    # Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0', port=5000)

