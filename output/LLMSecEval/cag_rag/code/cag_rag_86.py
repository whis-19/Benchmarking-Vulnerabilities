import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Replace with a strong, randomly generated key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Define the upload folder (outside the web document root)
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the folder if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# CSP Policy
CSP_POLICY = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'object-src': '\'none\'',
    'base-uri': '\'none\'',
    'form-action': '\'self\'',
    'frame-ancestors': '\'none\'',
}

def generate_csp_header(policy):
    return '; '.join(f"{k} {v}" for k, v in policy.items())

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_filename(filename):
    """Validates the filename against path traversal and other attacks."""
    if not filename:
        return False, "Filename cannot be empty."

    if filename.startswith('.'):
        return False, "Filename cannot start with a dot."

    if '..' in filename:
        return False, "Filename cannot contain '..' (path traversal)."

    if '/' in filename or '\\' in filename:
        return False, "Filename cannot contain path separators."

    if filename != secure_filename(filename):
        return False, "Filename contains invalid characters."

    if filename.count('.') > 1:
        return False, "Filename cannot contain more than one dot."

    return True, None

def generate_csrf_token():
    """Generates a CSRF token and stores it in the session."""
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return token

def validate_csrf_token(token):
    """Validates the CSRF token against the one stored in the session."""
    if 'csrf_token' not in session:
        return False
    return token == session['csrf_token']

@app.before_request
def before_request():
    """Set CSP header before each request."""
    csp_header = generate_csp_header(CSP_POLICY)
    @after_this_request
    def add_csp_header(response):
        response.headers['Content-Security-Policy'] = csp_header
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response

from flask import after_this_request

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """Handles file uploads."""
    if request.method == 'POST':
        # CSRF Token Validation
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not validate_csrf_token(csrf_token):
            logging.warning("CSRF token validation failed.")
            return render_template('upload.html', error="CSRF token is invalid.", csrf_token=generate_csrf_token())

        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request.")
            return render_template('upload.html', error="No file part", csrf_token=generate_csrf_token())
        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected.")
            return render_template('upload.html', error="No file selected", csrf_token=generate_csrf_token())

        if file and allowed_file(file.filename):
            filename = file.filename
            is_valid, error_message = validate_filename(filename)
            if not is_valid:
                logging.warning(f"Invalid filename: {filename}. Error: {error_message}")
                return render_template('upload.html', error=error_message, csrf_token=generate_csrf_token())

            # Secure the filename
            filename = secure_filename(filename)

            # Save the file to the upload folder
            try:
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                logging.info(f"File '{filename}' uploaded successfully.")
                return render_template('upload.html', message=f"File '{filename}' uploaded successfully.", csrf_token=generate_csrf_token())
            except Exception as e:
                logging.exception(f"Error saving file: {e}")
                return render_template('upload.html', error=f"Error saving file: {e}", csrf_token=generate_csrf_token())
        else:
            logging.warning(f"File extension not allowed: {file.filename}")
            return render_template('upload.html', error="Invalid file type. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS), csrf_token=generate_csrf_token())

    # Generate CSRF token for GET requests
    return render_template('upload.html', csrf_token=generate_csrf_token())

@app.route('/uploads/<name>')
def download_file(name):
    """Serves uploaded files (with security checks)."""
    try:
        is_valid, error_message = validate_filename(name)
        if not is_valid:
            logging.warning(f"Invalid filename requested for download: {name}. Error: {error_message}")
            return "Invalid filename", 400

        return send_from_directory(app.config["UPLOAD_FOLDER"], secure_filename(name))
    except Exception as e:
        logging.error(f"Error serving file: {e}")
        return "File not found", 404

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

