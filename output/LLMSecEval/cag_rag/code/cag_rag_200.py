import os
from functools import wraps
from flask import Flask, send_from_directory, abort, request, make_response
import secrets
import hashlib
from urllib.parse import urlparse

app = Flask(__name__)

# Configuration - Should be externalized in a real application
UPLOAD_FOLDER = 'images'  # Define the allowed upload folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions
CSRF_TOKEN_NAME = 'csrf_token'
SECRET_KEY = secrets.token_hex(32)  # Generate a strong secret key
app.secret_key = SECRET_KEY

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# CSP Header - Adjust as needed for your application
CSP_POLICY = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = CSP_POLICY
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


# CSRF Token Generation and Validation
def generate_csrf_token():
    return secrets.token_hex(16)

def validate_csrf_token(token):
    session_token = request.cookies.get(CSRF_TOKEN_NAME)
    if not session_token or not secrets.compare_digest(session_token, token):
        return False
    return True


# URL Validation (Allowlist approach)
ALLOWED_SCHEMES = {'http', 'https'}
ALLOWED_NETLOCS = {'localhost:5000', '127.0.0.1:5000'}  # Example: Add your domain(s) here

def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  Uses an allowlist approach.
    """
    try:
        url = urlparse(target)
        return (url.scheme in ALLOWED_SCHEMES and
                url.netloc in ALLOWED_NETLOCS)
    except:
        return False  # Handle parsing errors as unsafe


# File Extension Validation
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Path Sanitization and Validation
def sanitize_filepath(filename):
    """
    Sanitizes the filename to prevent path traversal attacks.
    """
    if ".." in filename:
        return None  # Reject path traversal attempts

    if filename.count(".") > 1:
        return None # Reject filenames with multiple dots

    return filename


def image_route(url):
    """
    Decorator to handle image requests.
    """
    def decorator(f):
        @app.route(url)
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator


@image_route('/image/<path:filename>')
def get_image(filename):
    """
    Serves an image file from the images directory.
    """
    # Sanitize the filename
    filename = sanitize_filepath(filename)
    if not filename:
        abort(400, "Invalid filename.")

    # Construct the full file path
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    # Check if the file exists and is within the allowed directory
    if not os.path.exists(filepath) or not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_FOLDER)):
        abort(404, "File not found.")

    # Check file extension
    if not allowed_file(filename):
        abort(400, "Invalid file type.")

    try:
        # Serve the file using send_from_directory (more secure than send_file)
        return send_from_directory(UPLOAD_FOLDER, filename)
    except Exception as e:
        print(f"Error serving file: {e}")  # Log the error
        abort(500, "Internal Server Error.")


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """
    Handles file uploads with CSRF protection.
    """
    if request.method == 'POST':
        # CSRF Validation
        csrf_token = request.form.get(CSRF_TOKEN_NAME)
        if not validate_csrf_token(csrf_token):
            abort(400, "CSRF token validation failed.")

        # Check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file'

        if file and allowed_file(file.filename):
            filename = sanitize_filepath(file.filename)
            if not filename:
                return "Invalid filename"

            # Secure filename generation (hash the original filename)
            file_extension = filename.rsplit('.', 1)[1].lower()
            hashed_filename = hashlib.sha256(filename.encode('utf-8')).hexdigest() + '.' + file_extension

            filepath = os.path.join(UPLOAD_FOLDER, hashed_filename)
            file.save(filepath)
            return f'File uploaded successfully.  Access it at /image/{hashed_filename}'

    # Generate CSRF token for GET requests
    csrf_token = generate_csrf_token()
    resp = make_response('''
    <!doctype html>
    <html>
    <head><title>Upload new File</title></head>
    <body>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=hidden name="{}" value="{}">
      <input type=submit value=Upload>
    </form>
    </body>
    </html>
    '''.format(CSRF_TOKEN_NAME, csrf_token))
    resp.set_cookie(CSRF_TOKEN_NAME, csrf_token, httponly=True, secure=True)  # Secure=True requires HTTPS
    return resp


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    A basic login example (replace with a proper authentication system).
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # In a real application, you would validate the username and password
        # against a database or other authentication system.
        if username == 'testuser' and password == 'testpass':
            # Create a session (replace with a proper session management)
            session_token = secrets.token_hex(32)
            resp = make_response("Login successful!")
            resp.set_cookie('session_token', session_token, httponly=True, secure=True)  # Secure=True requires HTTPS
            return resp
        else:
            return "Login failed."

    return '''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''


if __name__ == '__main__':
    # NEVER use debug=True in production!
    # Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0')

