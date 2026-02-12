# Example of using nonces for CSP (complete with template example)
import secrets
import os  # Import os for path manipulation
import logging  # Import logging for better error handling
from flask import Flask, render_template, request, after_request, send_from_directory  # Import send_from_directory
from flask_wtf.csrf import CSRFProtect
import bcrypt
import magic

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong, random key
csrf = CSRFProtect(app)

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'  # Store uploads outside the web root
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# CSP Policy (Restrictive!)
app.config['CSP_POLICY'] = {
    'default-src': "'none'",
    'script-src': "'self' 'nonce-{nonce}'",  # Allow scripts from self and with nonce
    'style-src': "'self' 'nonce-{nonce}'",   # Allow styles from self and with nonce
    'img-src': "'self' data:",              # Allow images from self and data URIs
    'font-src': "'self'",                   # Allow fonts from self
    'connect-src': "'self'",               # Allow AJAX/Fetch from self
    'frame-ancestors': "'none'",            # Prevent clickjacking
    'base-uri': "'self'",                   # Restrict base URL
    'form-action': "'self'",                # Restrict form submissions
    'object-src': "'none'",                 # Disallow plugins
    'report-uri': '/csp_report'             # Report CSP violations
}

# Fallback CSP Policy (Very Restrictive)
app.config['CSP_POLICY_STRING'] = "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none';"

# Mock Database (Replace with a real database!)
users = {}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


@app.route('/')
def index():
    nonce = secrets.token_urlsafe(16)
    csp_policy = app.config['CSP_POLICY'].copy()  # Copy to avoid modifying the original
    csp_policy['script-src'] = csp_policy['script-src'].format(nonce=nonce)
    csp_policy['style-src'] = csp_policy['style-src'].format(nonce=nonce)
    csp_header_value = '; '.join([f"{k} {v}" for k, v in csp_policy.items()])
    return render_template('index.html', nonce=nonce, csp_header_value=csp_header_value)


@app.route('/csp_report', methods=['POST'])
def csp_report():
    """
    Handles CSP reports.  Logs the reports for analysis.
    """
    report = request.get_json()
    logging.warning(f"CSP Violation: {report}")
    return '', 204  # Return a 204 No Content response


@app.after_request
def after_request(response):
    """
    Apply security headers to every response.
    """
    # Use the dynamically generated CSP header
    if hasattr(request, 'csp_header_value'):
        response.headers['Content-Security-Policy'] = request.csp_header_value
    else:
        response.headers['Content-Security-Policy'] = app.config['CSP_POLICY_STRING'] # Fallback

    response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevents MIME sniffing
    response.headers['X-Frame-Options'] = 'DENY'  # Prevents clickjacking
    # response.headers['X-XSS-Protection'] = '1; mode=block'  # Deprecated - Remove
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    return response


# Example of improved password hashing (using bcrypt) - requires installing bcrypt
# pip install bcrypt

def store_user_in_db(username, password):
    """
    Stores a user in the database (mock).
    """
    # Password complexity requirements (example)
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not any(char.isdigit() for char in password):
        raise ValueError("Password must contain at least one digit.")
    if not any(char.isupper() for char in password):
        raise ValueError("Password must contain at least one uppercase letter.")

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = {'password_hash': hashed_password, 'login_attempts': 0}  # Initialize login attempts


def check_password_hash(username, password):
    """
    Checks the password hash and handles account locking.
    """
    if username not in users:
        return False

    user = users[username]

    if user.get('login_attempts', 0) >= 5:  # Example: Lock after 5 failed attempts
        logging.warning(f"Account locked for user: {username}")
        return False  # Account locked

    if bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
        # Reset login attempts on successful login
        user['login_attempts'] = 0
        return True
    else:
        # Increment login attempts
        user['login_attempts'] = user.get('login_attempts', 0) + 1
        logging.warning(f"Failed login attempt for user: {username}, attempt: {user['login_attempts']}")
        return False


# Example of content type validation for file uploads (requires python-magic)
# pip install python-magic

def allowed_file(filename, file_content):
    """
    Checks if a file extension is allowed and validates content type.
    """
    extension = filename.rsplit('.', 1)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        logging.warning(f"Invalid file extension: {extension}")
        return False

    mime = magic.Magic(mime=True)
    mime_type = mime.from_buffer(file_content)

    # Example: Allow only images with specific MIME types
    if extension in ['png', 'jpg', 'jpeg', 'gif'] and not mime_type.startswith('image/'):
        logging.warning(f"Invalid MIME type: {mime_type} for extension: {extension}")
        return False

    return True


def validate_and_sanitize_filename(filename):
    """
    Validates and sanitizes the filename to prevent injection attacks and path traversal.
    Uses a whitelisting approach.
    """
    # Only allow alphanumeric characters, underscores, periods, and dashes
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
    sanitized_filename = ''.join(c for c in filename if c in allowed_chars)

    # Ensure the filename is not empty after sanitization
    if not sanitized_filename:
        logging.warning(f"Filename is empty after sanitization: {filename}")
        return None

    # Ensure the filename doesn't start with a dot (hidden file)
    if sanitized_filename.startswith('.'):
        logging.warning(f"Filename starts with a dot: {filename}")
        return None

    # Limit filename length
    max_filename_length = 255
    if len(sanitized_filename) > max_filename_length:
        sanitized_filename = sanitized_filename[:max_filename_length]
        logging.warning(f"Filename truncated due to length: {filename}")

    logging.info(f"Filename sanitized: {filename} -> {sanitized_filename}")
    return sanitized_filename


@app.route('/upload', methods=['GET', 'POST'])
@csrf.csrf_protect
def upload_file():
    """
    Handles file uploads.
    """
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in request")
            return 'No file part', 400  # Bad Request
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected")
            return 'No selected file', 400  # Bad Request

        try:
            file_content = file.read()

            # Check file size
            if len(file_content) > app.config['MAX_CONTENT_LENGTH']:
                logging.warning(f"File size exceeds limit: {len(file_content)} bytes")
                return 'File size exceeds the limit', 413  # Payload Too Large

            if allowed_file(file.filename, file_content):
                filename = validate_and_sanitize_filename(file.filename)
                if not filename:
                    return "Invalid filename", 400

                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                # Check for path traversal *after* joining the path
                absolute_filepath = os.path.abspath(filepath)
                absolute_upload_folder = os.path.abspath(app.config['UPLOAD_FOLDER'])

                if not absolute_filepath.startswith(absolute_upload_folder):
                    logging.warning(f"Path traversal attempt detected: {filepath}")
                    return "Invalid file path", 400

                # Write the file
                with open(filepath, 'wb') as f:
                    f.write(file_content)

                # Set file permissions (restrictive) - adjust as needed
                os.chmod(filepath, 0o644)  # Read/write for owner, read-only for others

                logging.info(f"File uploaded successfully: {filepath}")
                return 'File uploaded successfully'
            else:
                return 'Invalid file type or content', 400

        except Exception as e:
            logging.exception("Error during file upload")  # Log the full exception
            return 'An error occurred during file upload', 500  # Internal Server Error

    return render_template('upload.html')


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """
    Serves uploaded files securely.
    """
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)  # Force download


if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc")  # Enable HTTPS with a self-signed certificate for testing

