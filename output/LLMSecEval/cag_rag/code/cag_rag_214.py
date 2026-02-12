import os
import secrets
from flask import Flask, request, render_template, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'  # Relative to the app's root
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
app.config['SECRET_KEY'] = secrets.token_hex(16)  # For CSRF protection

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Utility Functions ---

def generate_csrf_token():
    """Generates a CSRF token."""
    return secrets.token_hex(32)

def validate_file_extension(filename, allowed_extensions=None):
    """Validates the file extension against an allowlist."""
    if allowed_extensions is None:
        allowed_extensions = {'pdf'}  # Default to PDF only
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def sanitize_filename(filename):
    """Sanitizes the filename using werkzeug's secure_filename and performs additional checks."""
    filename = secure_filename(filename)
    if filename is None or filename == "":
        return None  # Or raise an exception, depending on your needs

    # Additional checks to prevent path traversal and other issues
    if ".." in filename or "/" in filename or "\\" in filename:
        logging.warning(f"Detected potentially malicious filename: {filename}")
        return None

    if filename.count('.') > 1:
        logging.warning(f"Detected potentially malicious filename with multiple dots: {filename}")
        return None

    return filename

def is_safe_path(basedir, path):
    """
    Verifies that the given path is within the allowed base directory.
    Prevents path traversal vulnerabilities.
    """
    abs_basepath = os.path.abspath(basedir)
    abs_path = os.path.abspath(os.path.join(basedir, path))
    return abs_path.startswith(abs_basepath)

# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """Handles file uploads with security measures."""
    csrf_token = generate_csrf_token()
    if request.method == 'POST':
        # CSRF Validation
        if request.form.get('csrf_token') != csrf_token:
            logging.warning("CSRF token validation failed.")
            return render_template('upload.html', error='CSRF token invalid.', csrf_token=csrf_token)

        # File Handling
        if 'file' not in request.files:
            return render_template('upload.html', error='No file part', csrf_token=csrf_token)
        file = request.files['file']

        if file.filename == '':
            return render_template('upload.html', error='No selected file', csrf_token=csrf_token)

        if file:
            # Sanitize filename
            filename = sanitize_filename(file.filename)
            if filename is None:
                return render_template('upload.html', error='Invalid filename.', csrf_token=csrf_token)

            # Validate file extension
            if not validate_file_extension(filename):
                return render_template('upload.html', error='Invalid file extension. Only PDF files are allowed.', csrf_token=csrf_token)

            # Construct the full, safe filepath
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Ensure the path is safe (within the upload folder)
            if not is_safe_path(app.config['UPLOAD_FOLDER'], filename):
                logging.warning(f"Attempted path traversal: {filename}")
                return render_template('upload.html', error='Invalid filename.', csrf_token=csrf_token)

            try:
                file.save(filepath)
                logging.info(f"File saved successfully: {filepath}")
                return redirect(url_for('uploaded_file', filename=filename))
            except Exception as e:
                logging.exception("Error saving file:")
                return render_template('upload.html', error=f'Error saving file: {str(e)}', csrf_token=csrf_token)

    return render_template('upload.html', csrf_token=csrf_token)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serves uploaded files securely."""
    # Sanitize the filename before using it
    filename = sanitize_filename(filename)
    if filename is None:
        return "Invalid filename", 400

    # Ensure the path is safe before serving the file
    if not is_safe_path(app.config['UPLOAD_FOLDER'], filename):
        logging.warning(f"Attempted path traversal during file serving: {filename}")
        return "File not found", 404

    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logging.error(f"Error serving file: {e}")
        return "File not found", 404

@app.route('/download/<filename>')
def download_file(filename):
    """Allows secure downloading of files."""
    # Sanitize the filename
    filename = sanitize_filename(filename)
    if filename is None:
        return "Invalid filename", 400

    # Ensure the path is safe
    if not is_safe_path(app.config['UPLOAD_FOLDER'], filename):
        logging.warning(f"Attempted path traversal during file download: {filename}")
        return "File not found", 404

    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except Exception as e:
        logging.error(f"Error downloading file: {e}")
        return "File not found", 404

@app.after_request
def add_security_headers(response):
    """Adds security headers to every response."""
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --- Template ---
# Create a simple HTML template (upload.html) in a 'templates' folder:
# templates/upload.html
#
# <!DOCTYPE html>
# <html lang="en">
# <head>
#     <meta charset="UTF-8">
#     <meta name="viewport" content="width=device-width, initial-scale=1.0">
#     <title>File Upload</title>
# </head>
# <body>
#     <h1>Upload PDF File</h1>
#     {% if error %}
#         <p style="color: red;">{{ error }}</p>
#     {% endif %}
#     <form method="post" enctype="multipart/form-data">
#         <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
#         <input type="file" name="file">
#         <button type="submit">Upload</button>
#     </form>
# </body>
# </html>

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)

