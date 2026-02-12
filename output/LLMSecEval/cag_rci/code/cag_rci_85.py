import os
import logging
from datetime import datetime, timedelta
from flask import Flask, session, redirect, url_for, request
from werkzeug.utils import secure_filename
import magic  # For file content type checking
from flask_wtf.csrf import CSRFProtect  # For CSRF protection

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Example allowed extensions
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

# Initialize Flask app
app = Flask(__name__)

# *** CRITICAL: Generate and use a strong secret key ***
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24)

# Configure session settings
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE  # File size limit

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# File I/O Functions
def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def sanitize_filename(filename):
    """Sanitizes the filename to prevent path traversal and other attacks."""
    try:
        filename = secure_filename(filename)  # Werkzeug's secure_filename
        if not filename:
            raise ValueError("Invalid filename after secure_filename.")
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        filepath = os.path.abspath(filepath)  # Normalize the path
        if not filepath.startswith(os.path.abspath(UPLOAD_FOLDER)):
            raise ValueError("Path traversal detected.")
        return filename
    except ValueError as e:
        logging.warning(f"Rejected filename: {filename} - {e}")
        raise


def validate_file_content(file_path):
    """Validates the content of the uploaded file using python-magic."""
    try:
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(file_path)
        logging.info(f"Detected MIME type: {mime_type} for {file_path}")

        # Example: Allow only images and PDFs
        if not (mime_type.startswith('image/') or mime_type == 'application/pdf'):
            logging.warning(f"Rejected file content: {mime_type} for {file_path}")
            return False
        return True
    except Exception as e:
        logging.error(f"Error validating file content: {e}")
        return False


# Session Management
SESSION_TIMEOUT_MINUTES = 30

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    session.modified = True  # Ensure session is updated on each request

    # Check if the endpoint is excluded from session timeout
    if request.endpoint not in ['static']:  # Exclude static files
        if 'last_activity' in session:
            time_since_last_activity = datetime.now() - session['last_activity']
            if time_since_last_activity > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
                session.clear()  # Clear the session
                return redirect(url_for('login'))  # Redirect to login page
        session['last_activity'] = datetime.now()


# Routes
@app.route('/login')
def login():
    # Implement your login logic here (use strong password hashing!)
    return "Login Page"


@app.route('/')
def index():
    return "Index Page"


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        try:
            filename = sanitize_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)

            if validate_file_content(filepath):
                return "File uploaded successfully", 200
            else:
                os.remove(filepath)  # Remove invalid file
                return "Invalid file content", 400

        except ValueError as e:
            return str(e), 400
        except Exception as e:
            logging.exception("Error during file upload:")
            return "Upload failed", 500
    else:
        return "Invalid file type", 400


# Example route that requires CSRF protection
@app.route('/protected', methods=['POST'])
@csrf.exempt  # Remove this line when you implement proper CSRF handling in your forms
def protected():
    # This route is protected by CSRF.  Any POST request to this route
    # must include a valid CSRF token.  Flask-WTF handles this automatically
    # when you use its form classes.
    return "Protected resource accessed!"


# Static files route
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Enable HTTPS for local testing

