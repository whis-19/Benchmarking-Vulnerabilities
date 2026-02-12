# File Upload
import uuid  # Import UUID
import os
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, abort, current_app
from werkzeug.utils import secure_filename
import logging
import magic  # For content-type validation
from datetime import datetime
from flask_session import Session  # For session regeneration

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong secret key for sessions

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

# Ensure upload folder exists and has correct permissions
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.chmod(UPLOAD_FOLDER, 0o750)  # Owner: read/write/execute, Group: read/execute, Others: no access

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only enable if using HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # or 'Strict' depending on your needs
app.config['SESSION_TYPE'] = 'filesystem'  # Or 'redis', 'mongodb', etc.
Session(app)  # Initialize Flask-Session

# CSP Header
CSP_POLICY = {
    'default-src': "'self'",
    'script-src': "'self' 'nonce-randomstring'",  # Example with nonce
    'style-src': "'self'",
    'img-src': "'self' data:",
    'font-src': "'self'",
    'object-src': "'none'",
    'base-uri': "'none'",
    'form-action': "'self'",
    'frame-ancestors': "'none'",
    'upgrade-insecure-requests': '1', # Upgrade HTTP to HTTPS
    # Example report-uri (replace with your endpoint)
    # 'report-uri': '/csp_report',
}

def generate_csp_header(policy):
    """Generates a Content-Security-Policy header string."""
    csp_string = "; ".join([f"{k} {v}" for k, v in policy.items()])
    return csp_string

@app.after_request
def add_security_headers(response):
    """Adds security headers to each response."""
    nonce = secrets.token_urlsafe(16)  # Generate a random nonce
    response.headers['Content-Security-Policy'] = generate_csp_header({**CSP_POLICY, 'script-src': f"{CSP_POLICY['script-src']} 'nonce-{nonce}'"}) # Add nonce to CSP
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' # HSTS - Enable only if using HTTPS
    response.headers['Permissions-Policy'] = "geolocation=(), microphone=()" # Example Permissions-Policy
    response.headers['X-Nonce'] = nonce  # Add nonce to response headers for use in templates
    return response

# CSRF Decorator
def generate_csrf_token():
    """Generates a CSRF token."""
    return secrets.token_hex(16)

def validate_csrf(f):
    """Decorator to validate CSRF token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = session.pop('_csrf_token', None)
            form_token = request.form.get('_csrf_token')

            if not token or token != form_token:
                logging.warning(f"CSRF token validation failed. User IP: {request.remote_addr}") # Log user IP
                abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

def get_csrf_token():
    """Retrieves or generates a CSRF token for the session."""
    token = session.get('_csrf_token')
    if not token:
        token = generate_csrf_token()
        session['_csrf_token'] = token
    return token


def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """Sanitizes the filename to prevent path traversal and other attacks."""
    filename = secure_filename(filename)  # Werkzeug's secure_filename
    if filename.startswith('.'):
        logging.warning(f"Filename {filename} starts with a dot, rejecting.")
        return None  # Reject hidden files
    if ".." in filename:
        logging.warning(f"Filename {filename} contains '..', rejecting.")
        return None  # Reject path traversal attempts
    return filename

def validate_filepath(filepath):
    """Validates the filepath to prevent path traversal."""
    filepath = os.path.abspath(filepath)  # Get absolute path
    upload_folder_abs = os.path.abspath(app.config['UPLOAD_FOLDER'])

    if not filepath.startswith(upload_folder_abs):
        logging.warning(f"Filepath {filepath} is outside the allowed upload folder, rejecting.")
        return False

    if os.path.islink(filepath):
        logging.warning(f"Filepath {filepath} is a symbolic link, rejecting.")
        return False

    return True

@app.route('/', methods=['GET', 'POST'])
@validate_csrf  # Use the decorator!
def upload_file():
    csrf_token = get_csrf_token()
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request.")
            return render_template('upload.html', message='No file part', csrf_token=csrf_token)

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected.")
            return render_template('upload.html', message='No file selected', csrf_token=csrf_token)

        if file and allowed_file(file.filename):
            filename = sanitize_filename(file.filename)
            if not filename:
                return render_template('upload.html', message='Invalid filename', csrf_token=csrf_token)

            # Handle filename collisions - Use UUID
            base, ext = os.path.splitext(filename)
            filename = f"{uuid.uuid4()}{ext}"  # Use UUID for filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            if not validate_filepath(filepath):
                return render_template('upload.html', message='Invalid filepath', csrf_token=csrf_token)

            try:
                # Content-Type Validation (Example using python-magic)
                file_mime_type = magic.from_buffer(file.read(2048), mime=True) # Read the first 2048 bytes
                file.seek(0)  # Reset file pointer to the beginning
                if file_mime_type != 'application/pdf':
                    logging.warning(f"Invalid MIME type: {file_mime_type}")
                    return render_template('upload.html', message='Invalid file type.  Must be a PDF.', csrf_token=csrf_token)

                file.save(filepath)
                os.chmod(filepath, 0o640)  # Owner: read/write, Group: read, Others: no access
                logging.info(f"File saved successfully to {filepath}")
                session.regenerate() # Regenerate session ID after successful upload
                return render_template('upload.html', message=f'File uploaded successfully to {filename}', csrf_token=csrf_token)
            except Exception as e:
                logging.exception(f"Error saving file: {e}. User IP: {request.remote_addr}") # Log user IP
                return render_template('upload.html', message=f'Error uploading file: {str(e)}', csrf_token=csrf_token)
        else:
            logging.warning("Invalid file type.")
            return render_template('upload.html', message='Invalid file type. Only PDF files are allowed.', csrf_token=csrf_token)

    return render_template('upload.html', message='', csrf_token=csrf_token)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serves uploaded files securely."""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not validate_filepath(filepath):
        abort(400)  # Bad Request

    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True, download_name=filename) # Removed secure_filename
    except FileNotFoundError:
        abort(404)  # Not Found

# Example CSP Report Endpoint (replace with your logic)
@app.route('/csp_report', methods=['POST'])
def csp_report():
    """Handles CSP reports."""
    report_data = request.get_json()
    logging.warning(f"CSP Violation Report: {report_data}")
    return '', 204  # No Content

@app.errorhandler(403)
def forbidden(e):
    """Handles 403 Forbidden errors."""
    return render_template('error.html', error_code=403, message="Forbidden"), 403

@app.errorhandler(404)
def page_not_found(e):
    """Handles 404 Not Found errors."""
    return render_template('error.html', error_code=404, message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 Internal Server Errors."""
    logging.exception(f"Internal Server Error: {e}. User IP: {request.remote_addr}") # Log the full exception and user IP
    return render_template('error.html', error_code=500, message="Internal server error"), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

