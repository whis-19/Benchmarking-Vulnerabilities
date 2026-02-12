import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session
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
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# CSP Policy
CSP_POLICY = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'frame-ancestors': '\'none\'',
    'form-action': '\'self\''
}

def generate_csp_header(policy):
    return '; '.join([f"{k} {v}" for k, v in policy.items()])

@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = generate_csp_header(CSP_POLICY)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_csrf_token():
    """Generates a CSRF token."""
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return token

def validate_csrf_token(token):
    """Validates the CSRF token."""
    return 'csrf_token' in session and session['csrf_token'] == token

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """Handles file uploads with security measures."""
    if request.method == 'POST':
        # CSRF Token Validation
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not validate_csrf_token(csrf_token):
            logging.warning("CSRF token validation failed.")
            return render_template('upload.html', error='CSRF token is invalid.', csrf_token=generate_csrf_token())

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
            filename = secure_filename(file.filename) # Sanitize filename
            if filename.count('.') > 1:
                logging.warning("Invalid filename: Multiple dots.")
                return render_template('upload.html', error='Invalid filename: Multiple dots.', csrf_token=generate_csrf_token())

            if '/' in filename or '\\' in filename or '..' in filename:
                logging.warning("Invalid filename: Path traversal attempt.")
                return render_template('upload.html', error='Invalid filename: Path traversal attempt.', csrf_token=generate_csrf_token())

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                file.save(filepath)
                logging.info(f"File saved successfully to {filepath}")
                return render_template('upload.html', message='File uploaded successfully', csrf_token=generate_csrf_token())
            except Exception as e:
                logging.error(f"Error saving file: {e}")
                return render_template('upload.html', error=f'Error saving file: {e}', csrf_token=generate_csrf_token())
        else:
            logging.warning("Invalid file type.")
            return render_template('upload.html', error='Invalid file type. Allowed extensions: ' + ', '.join(ALLOWED_EXTENSIONS), csrf_token=generate_csrf_token())

    # Generate CSRF token for GET requests
    csrf_token = generate_csrf_token()
    return render_template('upload.html', csrf_token=csrf_token)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serves uploaded files (with security considerations)."""
    # While serving files directly is generally discouraged, if absolutely necessary:
    # 1.  Implement strong authentication and authorization.
    # 2.  Use a dedicated, isolated storage location.
    # 3.  Consider using a separate domain or subdomain for serving uploads.
    # 4.  Implement rate limiting to prevent abuse.
    # 5.  Never execute uploaded files directly.
    # 6.  Sanitize filenames and content before serving.

    # This is a placeholder and should be replaced with a more secure implementation
    # if direct file serving is required.  Consider using a CDN or object storage service.
    return "Direct file access is disabled for security reasons." # Or redirect to a download handler.

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

