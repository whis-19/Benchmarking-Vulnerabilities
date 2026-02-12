import os
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong secret key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define upload directory and allowed extensions
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# CSP Header
CSP = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'frame-ancestors': '\'none\'',
    'form-action': '\'self\'',
}

def set_csp_header(response):
    csp_value = '; '.join(f"{k} {v}" for k, v in CSP.items())
    response.headers['Content-Security-Policy'] = csp_value
    return response

app.after_request(set_csp_header)


# CSRF protection
def generate_csrf_token():
    session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = session.pop('csrf_token', None)
            if not token or token != request.form.get('csrf_token'):
                logging.warning("CSRF token validation failed.")
                return render_template('error.html', message="CSRF token is invalid."), 400
        return f(*args, **kwargs)
    return decorated_function

@app.route('/csrf_token')
def csrf_token():
    return generate_csrf_token()

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """Sanitizes the filename to prevent path traversal and other attacks."""
    if not filename:
        return None

    filename = secure_filename(filename)  # Werkzeug's secure_filename
    if filename is None or filename == "":
        return None

    if ".." in filename:
        logging.warning(f"Filename contains '..': {filename}")
        return None

    if "/" in filename or "\\" in filename:
        logging.warning(f"Filename contains path separators: {filename}")
        return None

    if filename.startswith("."):
        logging.warning(f"Filename starts with '.': {filename}")
        return None

    if len(filename.split(".")) > 2:
        logging.warning(f"Filename contains multiple dots: {filename}")
        return None

    return filename

def validate_filepath(filepath):
    """Validates the filepath against an allowlist and prevents traversal."""

    if not filepath:
        return False

    if ".." in filepath:
        logging.warning(f"Filepath contains '..': {filepath}")
        return False

    if "/" in filepath or "\\" in filepath:
        logging.warning(f"Filepath contains path separators: {filepath}")
        return False

    if len(filepath.split(".")) > 2:
        logging.warning(f"Filepath contains multiple dots: {filepath}")
        return False

    # Example allowlist (modify as needed)
    allowed_patterns = [r"^[a-zA-Z0-9_-]+\.(txt|pdf|png|jpg|jpeg|gif)$"]
    import re
    for pattern in allowed_patterns:
        if re.match(pattern, filepath):
            return True

    logging.warning(f"Filepath does not match allowlist: {filepath}")
    return False


@app.route('/', methods=['GET', 'POST'])
@validate_csrf
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return render_template('error.html', message='No file part'), 400

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return render_template('error.html', message='No selected file'), 400

        if file and allowed_file(file.filename):
            filename = sanitize_filename(file.filename)
            if not filename:
                return render_template('error.html', message='Invalid filename'), 400

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            if not validate_filepath(filename):
                return render_template('error.html', message='Invalid filepath'), 400

            try:
                file.save(filepath)
                logging.info(f"File saved successfully to {filepath}")
                return redirect(url_for('uploaded_file', filename=filename))
            except Exception as e:
                logging.exception("Error saving file:")
                return render_template('error.html', message=f'Error saving file: {str(e)}'), 500

        else:
            return render_template('error.html', message='Invalid file type'), 400

    return render_template('upload.html', csrf_token=generate_csrf_token())

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logging.error(f"Error serving file: {e}")
        return render_template('error.html', message='File not found'), 404

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message='Page not found'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', message='Internal server error'), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

