import os
from functools import wraps
from flask import Flask, request, send_file, abort, make_response
import secrets
import hashlib
import hmac
from urllib.parse import urlparse

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a strong secret key

# --- Security Configuration ---
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
IMAGE_UPLOAD_FOLDER = 'images'  # Define a safe folder for images
ALLOWED_DOMAINS = ['example.com', 'localhost']  # Example allowed domains

# Ensure the image directory exists
os.makedirs(IMAGE_UPLOAD_FOLDER, exist_ok=True)


# --- CSRF Protection ---
def generate_csrf_token():
    return secrets.token_hex(16)


def verify_csrf_token(token):
    session_token = request.cookies.get('csrf_token')
    if not session_token or not hmac.compare_digest(session_token, token):
        return False
    return True


# --- CSP Header ---
@app.after_request
def add_csp_header(response):
    csp = "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self';"
    response.headers['Content-Security-Policy'] = csp
    return response


# --- Route Decorator with Security ---
def secure_route(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Validate HTTPS
        if not request.is_secure:
            return "HTTPS is required", 400

        # Validate Referer (example, adjust as needed)
        referer = request.headers.get('Referer')
        if referer:
            parsed_url = urlparse(referer)
            if parsed_url.netloc not in ALLOWED_DOMAINS:
                return "Invalid Referer", 403

        return f(*args, **kwargs)

    return decorated_function


# --- File Serving Function ---
@app.route('/img')
@secure_route
def img():
    filename = request.args.get('name')

    if not filename:
        return "Filename is required", 400

    # --- Input Validation and Sanitization ---

    # Prevent path traversal attacks
    if ".." in filename:
        return "Invalid filename", 400

    # Check for multiple dots
    if filename.count('.') > 1:
        return "Invalid filename", 400

    # Validate file extension
    file_extension = filename.rsplit('.', 1)[-1].lower()
    if file_extension not in ALLOWED_IMAGE_EXTENSIONS:
        return "Invalid file extension", 400

    # Construct the full file path
    filepath = os.path.join(IMAGE_UPLOAD_FOLDER, filename)

    # Check if the file exists within the allowed directory
    if not os.path.isfile(filepath):
        return "File not found", 404

    # Normalize the path and check if it's still within the allowed directory
    filepath = os.path.normpath(filepath)
    if not filepath.startswith(os.path.abspath(IMAGE_UPLOAD_FOLDER) + os.sep):
        return "Invalid file path", 400

    try:
        # --- File Handling ---
        return send_file(filepath, mimetype=f'image/{file_extension}')  # Set correct mimetype
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        print(f"Error serving file: {e}")  # Log the error
        return "Internal Server Error", 500


# --- Example CSRF Protected Route (for state-changing operations) ---
@app.route('/upload', methods=['POST'])
@secure_route
def upload_image():
    csrf_token = request.form.get('csrf_token')
    if not verify_csrf_token(csrf_token):
        return "CSRF token is invalid", 400

    # --- File Upload Logic (Example) ---
    if 'image' not in request.files:
        return "No image part", 400

    image_file = request.files['image']

    if image_file.filename == '':
        return "No selected image", 400

    # --- Input Validation and Sanitization (File Upload) ---
    filename = image_file.filename
    if ".." in filename:
        return "Invalid filename", 400

    file_extension = filename.rsplit('.', 1)[-1].lower()
    if file_extension not in ALLOWED_IMAGE_EXTENSIONS:
        return "Invalid file extension", 400

    # Generate a secure filename (optional)
    secure_filename = secrets.token_hex(16) + "." + file_extension
    filepath = os.path.join(IMAGE_UPLOAD_FOLDER, secure_filename)

    try:
        image_file.save(filepath)
        return "Image uploaded successfully"
    except Exception as e:
        print(f"Error uploading image: {e}")
        return "Internal Server Error", 500


# --- Example Route to Generate CSRF Token ---
@app.route('/csrf_token')
@secure_route
def get_csrf_token():
    token = generate_csrf_token()
    resp = make_response({'csrf_token': token})
    resp.set_cookie('csrf_token', token, httponly=True, secure=True, samesite='Strict')  # Secure cookie
    return resp


if __name__ == '__main__':
    #  Never use debug mode in production!
    app.run(debug=False, host='0.0.0.0', port=443, ssl_context='adhoc') # Use adhoc for testing, replace with real certs in production

