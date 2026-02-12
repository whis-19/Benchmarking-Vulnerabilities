import cgi
import os
import secrets
import re

from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Replace with a strong, randomly generated key

# --- Security Configuration ---
CONTENT_SECURITY_POLICY = {
    'default-src': "'self'",
    'script-src': "'self'",
    'style-src': "'self'",
    'img-src': "'self' data:",
    'font-src': "'self'",
    'object-src': "'none'",
}

def set_csp_header(response):
    csp_value = "; ".join(f"{k} {v}" for k, v in CONTENT_SECURITY_POLICY.items())
    response.headers['Content-Security-Policy'] = csp_value
    return response

@app.after_request
def apply_security_headers(response):
    response = set_csp_header(response)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --- CSRF Protection ---
def generate_csrf_token():
    session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    return 'csrf_token' in session and session['csrf_token'] == token

def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or not validate_csrf_token(token):
                return "CSRF token validation failed.", 400
        return f(*args, **kwargs)
    return decorated_function

# --- File Handling Security ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Allowlist of file extensions
SAFE_FOLDER = os.path.abspath("safe_files") # Define a safe folder

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

if not os.path.exists(SAFE_FOLDER):
    os.makedirs(SAFE_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SAFE_FOLDER'] = SAFE_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """Sanitizes a filename to prevent path traversal and other attacks."""
    # Remove any characters that are not alphanumeric, underscores, or dots
    filename = re.sub(r"[^a-zA-Z0-9_.]", "", filename)
    # Remove leading and trailing dots
    filename = filename.strip(".")
    # Replace multiple dots with a single dot
    filename = re.sub(r"\.+", ".", filename)
    return filename

def is_safe_filepath(filepath):
    """
    Checks if a filepath is safe.

    This function performs several checks to ensure that the filepath is safe:
    1. It checks for directory separators ("/" or "\").
    2. It checks for ".." sequences.
    3. It checks for more than one "." character in a path component.
    4. It checks if the filepath is contained within a safe folder.

    Args:
        filepath (str): The filepath to check.

    Returns:
        bool: True if the filepath is safe, False otherwise.
    """
    if "/" in filepath or "\\" in filepath:
        return False
    if ".." in filepath:
        return False
    if any(component.count(".") > 1 for component in filepath.split(os.path.sep)):
        return False

    # Check if the filepath is contained within the safe folder
    abs_filepath = os.path.abspath(os.path.join(app.config['SAFE_FOLDER'], filepath))
    if not abs_filepath.startswith(os.path.abspath(app.config['SAFE_FOLDER'])):
        return False

    return True

# --- Routes ---
@app.route('/')
def index():
    csrf_token = generate_csrf_token()
    return render_template('index.html', csrf_token=csrf_token)

@app.route('/scan', methods=['POST'])
@csrf_required
def scan():
    user_input = request.form.get('user_input', '')

    # Input Validation and Sanitization
    if not user_input:
        return "Error: Input cannot be empty.", 400

    # Escape user input for display in HTML
    escaped_input = cgi.escape(user_input)

    # Simulate reading with a maximum length
    max_length = 1023
    read_length = min(len(user_input), max_length)
    scanned_string = user_input[:read_length]

    # Simulate reading the newline (not stored)
    if len(user_input) > read_length:
        newline_char = user_input[read_length]
        if newline_char != '\n':
            return "Error: Expected newline character after input.", 400
        read_length += 1  # Account for the newline character

    return render_template('scan_result.html', scanned_string=escaped_input, read_length=read_length)

@app.route('/upload', methods=['GET', 'POST'])
@csrf_required
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file', 400

        if file and allowed_file(file.filename):
            filename = sanitize_filename(file.filename)
            # Ensure the filename is not empty after sanitization
            if not filename:
                return "Invalid filename after sanitization.", 400

            # Construct the full path within the safe folder
            filepath = os.path.join(app.config['SAFE_FOLDER'], filename)

            # Check if the filepath is safe
            if not is_safe_filepath(filename):
                return "Unsafe filepath.", 400

            try:
                file.save(filepath)
                return render_template('upload_success.html', filename=filename)
            except Exception as e:
                return f"Error saving file: {str(e)}", 500
        else:
            return 'Invalid file type. Allowed types: ' + ', '.join(ALLOWED_EXTENSIONS), 400
    csrf_token = generate_csrf_token()
    return render_template('upload.html', csrf_token=csrf_token)

@app.route('/uploads/<filename>')
def download_file(filename):
    """Serve files from the upload directory."""

    # Sanitize the filename before using it
    filename = sanitize_filename(filename)

    # Check if the filename is safe
    if not is_safe_filepath(filename):
        return "Unsafe filepath.", 400

    try:
        return send_from_directory(app.config['SAFE_FOLDER'], filename)
    except Exception as e:
        return f"Error serving file: {str(e)}", 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

