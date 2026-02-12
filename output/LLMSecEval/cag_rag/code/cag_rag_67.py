import os
from functools import wraps
from flask import Flask, send_file, abort, request, make_response
import secrets
import hashlib
from urllib.parse import urlparse

app = Flask(__name__)

# Configuration -  Adjust these as needed
UPLOAD_FOLDER = 'images'  # Define the safe upload folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed file extensions
CSP_POLICY = "default-src 'self'"  # Example CSP policy - customize as needed
SECRET_KEY = secrets.token_hex(32)  # Generate a strong secret key
app.secret_key = SECRET_KEY

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# CSRF token generation and validation
def generate_csrf_token():
    return secrets.token_hex(16)


def validate_csrf_token(token):
    session_token = request.cookies.get('csrf_token')
    if not session_token or not secrets.compare_digest(session_token, token):
        return False
    return True


# Decorator for routes requiring CSRF protection
def csrf_protected(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.form.get('csrf_token')
        if not token or not validate_csrf_token(token):
            abort(403)  # Forbidden
        return fn(*args, **kwargs)

    return wrapper


# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_safe_path(basedir, path, max_dots=1):
    """
    Safely checks if a path is within a basedir and prevents path traversal.
    Limits the number of dots allowed in the path.
    """
    if not path:
        return False

    if path.count("..") > 0:
        return False

    if path.count(".") > max_dots:
        return False

    abs_basedir = os.path.abspath(basedir)
    abs_path = os.path.abspath(os.path.join(basedir, path))
    return abs_path.startswith(abs_basedir)


def sanitize_filename(filename):
    """Sanitizes a filename to prevent directory traversal and other attacks."""
    # Remove any characters that aren't alphanumeric, underscores, or dots
    filename = "".join(c for c in filename if c.isalnum() or c in ('.', '_'))
    # Remove leading/trailing whitespace
    filename = filename.strip()
    return filename


def validate_url(url):
    """Validates a URL to prevent malicious redirects."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])  # Must have scheme and netloc
    except:
        return False


# Route decorator and handler
def image_route(url):
    def decorator(f):
        @app.route(url)
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)

        return wrapper

    return decorator


@image_route('/image/<filename>')
def get_image(filename):
    """
    Serves an image file from the 'images' folder.
    """
    # Sanitize the filename
    filename = sanitize_filename(filename)

    # Validate the filename
    if not filename:
        abort(400)  # Bad Request

    # Construct the full file path
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    # Prevent path traversal
    if not is_safe_path(UPLOAD_FOLDER, filename):
        abort(400)  # Bad Request - Possible path traversal attempt

    # Check if the file exists
    if not os.path.isfile(filepath):
        abort(404)  # Not Found

    try:
        # Send the file with appropriate headers
        return send_file(filepath)
    except Exception as e:
        print(f"Error sending file: {e}")
        abort(500)  # Internal Server Error


@app.route('/upload', methods=['POST'])
@csrf_protected
def upload_image():
    """Handles image uploads with security checks."""
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    if file and allowed_file(file.filename):
        filename = sanitize_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)

        if not is_safe_path(UPLOAD_FOLDER, filename):
            return "Invalid filename", 400

        try:
            file.save(filepath)
            return "File uploaded successfully", 200
        except Exception as e:
            print(f"Error saving file: {e}")
            return "Error uploading file", 500
    else:
        return "Invalid file type", 400


@app.after_request
def add_security_headers(response):
    """Adds security headers to every response."""
    response.headers['Content-Security-Policy'] = CSP_POLICY
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'  # Prevent caching sensitive data
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/get_csrf')
def get_csrf():
    """Endpoint to get a CSRF token."""
    token = generate_csrf_token()
    resp = make_response({"csrf_token": token})
    resp.set_cookie('csrf_token', token, httponly=True, samesite='Strict')  # Secure cookie
    return resp


@app.route('/form')
def form():
    """Simple form to demonstrate CSRF protection."""
    csrf_token = request.cookies.get('csrf_token')
    if not csrf_token:
        csrf_token = generate_csrf_token()
        resp = make_response(
            """
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="{}">
                <input type="file" name="file">
                <input type="submit" value="Upload">
            </form>
            """.format(csrf_token)
        )
        resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict')
        return resp
    else:
        return """
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="{}">
                <input type="file" name="file">
                <input type="submit" value="Upload">
            </form>
            """.format(csrf_token)


if __name__ == '__main__':
    app.run(debug=False, ssl_context='adhoc')  # Use HTTPS in production

