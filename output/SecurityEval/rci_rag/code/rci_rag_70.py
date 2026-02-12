import re
import os
import uuid
from flask import request, Flask, abort, make_response, session
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
# from pyclamd import ClamdNetworkSocket, ConnectionError # Import if using ClamAV

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'  # Store uploads in a dedicated folder
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)  # Set a strong secret key from environment variable or generate a random one
# Rate limiting configuration
app.config['FLASK_LIMITER_ENABLED'] = True
app.config['FLASK_LIMITER_STORAGE_URI'] = "memory://"  # Use in-memory storage for simplicity (consider Redis for production)
app.config['FLASK_LIMITER_DEFAULT_LIMITS'] = ["200 per day", "50 per hour"] # Example rate limits

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Strict allowlist for file extensions

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=app.config['FLASK_LIMITER_STORAGE_URI'],
    default_limits=app.config['FLASK_LIMITER_DEFAULT_LIMITS']
)

def allowed_file(filename):
    """
    Checks if the file extension is in the allowed list (case-insensitive).
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])  # Use POST for file uploads
@limiter.limit("10/minute") # Apply rate limiting to the upload endpoint
def upload():
    """
    Handles file uploads, validates username, filename, and file type.
    """
    username = request.form.get('username')  # Get username from form data
    file = request.files.get('file')  # Get the uploaded file

    # Validate username (stringent allowlist)
    if not username or not re.match(r"^[a-zA-Z0-9_-]+$", username):
        abort(400, "Invalid username.  Only alphanumeric characters, underscores, and hyphens are allowed.")

    # Validate file existence
    if not file:
        abort(400, "No file part")

    # Validate filename
    if file.filename == '':
        abort(400, "No selected file")

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Sanitize filename
        if not filename:
            abort(400, "Invalid filename after sanitization.")

        # More robust filename sanitization (disallow '..' and reserved characters)
        if ".." in filename or any(c in filename for c in r'\/:*?"<>|'):
            abort(400, "Filename contains invalid characters.")

        # Remove username check - no longer needed
        # if username.lower() not in filename.lower():
        #     abort(400, "Username not found in filename.")

        # Use UUID for filename to prevent collisions and further reduce attack surface
        filename = str(uuid.uuid4()) + "." + file.filename.rsplit('.', 1)[1].lower()

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # # File Content Scanning (ClamAV Example - Requires ClamAV and pyclamd)
        # try:
        #     cd = ClamdNetworkSocket()
        #     if cd.ping():
        #         scan_result = cd.scan(filepath)
        #         if scan_result:
        #             logging.error(f"Virus found in {filename}: {scan_result}")
        #             os.remove(filepath)
        #             abort(400, "Virus detected in uploaded file.")
        #     else:
        #         logging.warning("ClamAV not available.")
        #         # Consider failing the upload if ClamAV is critical
        # except ConnectionError:
        #     logging.error("ClamAV connection error.")
        #     abort(500, "Failed to scan file for viruses.") # Or a more user-friendly message

        try:
            file.save(filepath)
            logging.info(f"File uploaded successfully: {filename} by user {username}") # Log the upload
        except Exception as e:
            logging.exception(f"Error saving file {filename}: {e}") # Log the full exception
            abort(500, "File upload failed.") # Generic error message

        response = make_response("File uploaded successfully.") # Consider removing the filepath from the response
        response.headers['Content-Type'] = 'text/plain; charset=utf-8' # Correct Content-Type
        response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
        response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline';" # Refined CSP
        return response
    else:
        abort(400, "Invalid file type. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS))

# Example of session management (requires more complete implementation)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    # ... authentication logic ...
    if username == "test" and password == "test": # Replace with real authentication
        session['username'] = username
        session.regenerate() # Regenerate session ID after login
        return "Logged in successfully"
    else:
        abort(401, "Invalid credentials")

@app.route('/logout')
def logout():
    session.pop('username', None) # Remove username from session
    return "Logged out"

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Prevent clickjacking
    response.headers['X-XSS-Protection'] = '1; mode=block'  # Enable XSS protection
    response.headers['Cache-Control'] = 'no-store' # Prevent caching
    response.headers['Pragma'] = 'no-cache' # Prevent caching
    response.headers['Expires'] = '0' # Prevent caching
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' # Enable HSTS
    return response

@app.route('/')
def index():
    """
    Simple index route.
    """
    response = make_response("<h1>File Upload Example</h1><p>Upload files to the /upload endpoint.</p>")
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

