from flask import Flask, request, abort, jsonify
import lxml.etree
import os
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import hashlib
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# In-memory user database (replace with a secure database in production)
users = {
    "testuser": generate_password_hash("P@$$wOrd")  # Example: Replace with a strong, unique password
}

# Secret key for session management (replace with a strong, randomly generated key)
app.secret_key = secrets.token_hex(32)

# Allowed file extensions (restrict to only necessary types)
ALLOWED_EXTENSIONS = {'xml'}

# Upload directory (configure appropriately)
UPLOAD_DIRECTORY = 'uploads'
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)  # Create the directory if it doesn't exist

# Rate limiting (example - implement a more robust solution)
login_attempts = {}  # Store login attempts per IP address
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_TIME = 60  # seconds


def checkPassword(userid, password):
    """
    Checks the provided password against the stored hash for the given userid.
    Uses werkzeug.security for secure password hashing.
    """
    if userid in users:
        return check_password_hash(users[userid], password)
    return False


def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def sanitize_filename(filename):
    """
    Sanitizes the filename to prevent path traversal and other attacks.
    """
    # Remove any characters that are not alphanumeric, underscores, or dots
    filename = ''.join(c for c in filename if c.isalnum() or c in ['.', '_'])
    # Ensure the filename doesn't start with a dot
    if filename.startswith('.'):
        filename = '_' + filename[1:]
    return filename


@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad Request', 'message': str(error)}), 400


@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized', 'message': str(error)}), 401


@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden', 'message': str(error)}), 403


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'error': 'Internal Server Error', 'message': str(error)}), 500


@app.post("/upload")
def upload():
    """
    Handles XML file uploads, authenticates users, and performs basic XML validation.
    """
    try:
        userid = request.form.get('userid')
        password = request.form.get('password')
        file = request.files.get('file')

        # Input validation
        if not userid or not password or not file:
            logging.warning("Missing userid, password, or file.")
            abort(400, "Missing userid, password, or file.")

        # Rate limiting
        client_ip = request.remote_addr
        if client_ip in login_attempts and login_attempts[client_ip]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            time_elapsed = time.time() - login_attempts[client_ip]['last_attempt']
            if time_elapsed < LOGIN_LOCKOUT_TIME:
                logging.warning(f"Rate limit exceeded for IP: {client_ip}")
                abort(403, "Too many login attempts. Please try again later.")
            else:
                login_attempts[client_ip]['attempts'] = 0  # Reset attempts after lockout

        # Authentication
        if not checkPassword(userid, password):
            if client_ip not in login_attempts:
                login_attempts[client_ip] = {'attempts': 0, 'last_attempt': time.time()}
            login_attempts[client_ip]['attempts'] += 1
            login_attempts[client_ip]['last_attempt'] = time.time()
            logging.warning(f"Authentication failed for user: {userid} from IP: {client_ip}")
            abort(401, "Invalid credentials.")

        # Reset login attempts on successful login
        if client_ip in login_attempts:
            del login_attempts[client_ip]

        # File validation
        if file and allowed_file(file.filename):
            filename = sanitize_filename(file.filename)
            filepath = os.path.join(UPLOAD_DIRECTORY, filename)

            # Prevent overwriting existing files (optional)
            if os.path.exists(filepath):
                logging.warning(f"File already exists: {filepath}")
                abort(400, "File already exists.")

            # Save the file
            file.save(filepath)
            logging.info(f"File saved to: {filepath}")

            # XML Validation (basic example)
            try:
                tree = lxml.etree.parse(filepath)
                logging.info("XML validation successful.")
            except lxml.etree.XMLSyntaxError as e:
                logging.error(f"XML validation error: {e}")
                os.remove(filepath)  # Remove invalid file
                abort(400, f"Invalid XML file: {e}")

            return jsonify({"message": "File uploaded successfully."}), 200
        else:
            logging.warning("Invalid file type.")
            abort(400, "Invalid file type.")

    except Exception as e:
        logging.exception("An error occurred during file upload.")
        abort(500, str(e))


if __name__ == '__main__':
    import time
    app.run(debug=True, host="0.0.0.0", ssl_context='adhoc') # Use HTTPS in production

