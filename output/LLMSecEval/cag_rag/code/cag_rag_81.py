import os
import secrets
from flask import Flask, request, render_template, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Replace with a strong, randomly generated key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the upload folder and allowed extensions
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
}

def generate_csp_header(policy):
    """Generates the Content-Security-Policy header."""
    return '; '.join(f"{k} {v}" for k, v in policy.items())

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit file size to 16MB

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_filename(filename):
    """
    Validates the filename to prevent path traversal and other attacks.
    """
    if not filename:
        return False

    if filename.startswith('.'):
        return False

    if filename.count('.') > 1:
        return False

    if '/' in filename or '\\' in filename:
        return False

    if ".." in filename:
        return False

    return True

def generate_csrf_token():
    """Generates a CSRF token."""
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return token

def validate_csrf_token(token):
    """Validates the CSRF token."""
    return 'csrf_token' in session and session['csrf_token'] == token

@app.before_request
def before_request():
    """Set CSP header before each request."""
    csp_header = generate_csp_header(CSP_POLICY)
    @request.after_request
    def add_csp_header(response):
        response.headers['Content-Security-Policy'] = csp_header
        return response

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """Handles file uploads."""
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf_token()

    if request.method == 'POST':
        # CSRF Token Validation
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not validate_csrf_token(csrf_token):
            logging.warning("CSRF token validation failed.")
            return render_template('upload.html', error='CSRF token is invalid.', csrf_token=session['csrf_token'])

        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request.")
            return render_template('upload.html', error='No file part', csrf_token=session['csrf_token'])

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected.")
            return render_template('upload.html', error='No selected file', csrf_token=session['csrf_token'])

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)  # Sanitize filename
            if not is_safe_filename(filename):
                logging.warning(f"Unsafe filename: {filename}")
                return render_template('upload.html', error='Invalid filename.', csrf_token=session['csrf_token'])

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                file.save(filepath)
                logging.info(f"File saved successfully to: {filepath}")
                return redirect(url_for('uploaded_file', filename=filename))
            except Exception as e:
                logging.exception("Error saving file.")
                return render_template('upload.html', error=f'Error saving file: {str(e)}', csrf_token=session['csrf_token'])
        else:
            logging.warning(f"Invalid file type uploaded: {file.filename}")
            return render_template('upload.html', error='Invalid file type. Only PDF files are allowed.', csrf_token=session['csrf_token'])

    return render_template('upload.html', csrf_token=session['csrf_token'])

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serves the uploaded file."""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logging.error(f"Error serving file: {filename} - {e}")
        return "File not found.", 404

@app.errorhandler(404)
def page_not_found(e):
    """Handles 404 errors."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 errors."""
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Only for development!  Never use this in production.
    app.run(debug=True, host="0.0.0.0", port=5000)

