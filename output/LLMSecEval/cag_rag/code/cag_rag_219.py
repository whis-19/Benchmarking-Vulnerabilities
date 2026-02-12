import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session
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
}

def generate_csp_header(policy):
    return '; '.join(f"{k} {v}" for k, v in policy.items())

app.config['CSP_HEADER'] = generate_csp_header(CSP_POLICY)

@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = app.config['CSP_HEADER']
    return response

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_csrf_token():
    """Generates a CSRF token and stores it in the session."""
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return token

def validate_csrf_token(token):
    """Validates the CSRF token against the one in the session."""
    return 'csrf_token' in session and session['csrf_token'] == token

def sanitize_filename(filename):
    """Sanitizes the filename to prevent path traversal and other attacks."""
    if not filename:
        return None

    # Secure filename using werkzeug's secure_filename
    filename = secure_filename(filename)

    # Check for directory separators
    if '/' in filename or '\\' in filename:
        logging.warning("Filename contains directory separators: %s", filename)
        return None

    # Check for ".." sequences
    if '..' in filename:
        logging.warning("Filename contains '..' sequence: %s", filename)
        return None

    # Check for multiple dots
    if filename.count('.') > 1:
        logging.warning("Filename contains multiple dots: %s", filename)
        return None

    return filename

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """Handles file uploads."""
    if request.method == 'POST':
        # CSRF Token Validation
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not validate_csrf_token(csrf_token):
            logging.warning("CSRF token validation failed.")
            return render_template('upload.html', error='CSRF token validation failed.', csrf_token=generate_csrf_token())

        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request.")
            return render_template('upload.html', error='No file part', csrf_token=generate_csrf_token())
        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected.")
            return render_template('upload.html', error='No selected file', csrf_token=generate_csrf_token())

        if file and allowed_file(file.filename):
            filename = sanitize_filename(file.filename)
            if not filename:
                return render_template('upload.html', error='Invalid filename.', csrf_token=generate_csrf_token())

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                file.save(filepath)
                logging.info("File saved successfully: %s", filepath)
                return redirect(url_for('uploaded_file', filename=filename))
            except Exception as e:
                logging.exception("Error saving file: %s", e)
                return render_template('upload.html', error=f'Error saving file: {e}', csrf_token=generate_csrf_token())
        else:
            logging.warning("File extension not allowed.")
            return render_template('upload.html', error='Invalid file type. Allowed types: ' + ', '.join(ALLOWED_EXTENSIONS), csrf_token=generate_csrf_token())

    return render_template('upload.html', csrf_token=generate_csrf_token(), error=None)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serves the uploaded file."""
    try:
        # Securely serve the file using send_from_directory
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logging.error("Error serving file: %s", e)
        return "File not found.", 404

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

