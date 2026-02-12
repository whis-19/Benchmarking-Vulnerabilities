from flask import Flask, make_response, request, abort, send_from_directory
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String
from html import escape
import secrets
import hashlib
import mimetypes  # For basic MIME type detection
import magic  # For content-based file type validation (install python-magic)
import logging
from werkzeug.utils import secure_filename  # For robust filename sanitization
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import subprocess  # For ClamAV integration
import uuid  # For generating unique filenames
from sqlalchemy import event  # For SQLite foreign key enforcement
from sqlalchemy.exc import IntegrityError  # For handling database integrity errors

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables from .env file (if it exists)
load_dotenv()

# Default database URI (override with environment variable)
DEFAULT_DATABASE_URI = 'sqlite:///:memory:'  # In-memory SQLite for testing

# Constants
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Example allowed extensions

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example rate limits
)

def configure_app(app):
    """
    Configures the Flask app with database settings and security configurations.
    """

    # Get database URI from environment variable, or use the default
    database_uri = os.environ.get('DATABASE_URI', DEFAULT_DATABASE_URI)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking for performance

    # **CRITICAL:** Set a strong, persistent secret key in production.  Do NOT use os.urandom in production.
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        logger.warning("No SECRET_KEY found in environment. Generating a temporary one.  THIS IS NOT SECURE FOR PRODUCTION.")
        secret_key = secrets.token_hex(24)
    app.config['SECRET_KEY'] = secret_key

    # Ensure the upload folder exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE  # Configure max upload size

    # Security Headers (important for production)
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # CSP - Strive to eliminate 'unsafe-inline' in production.  Use nonces or hashes.
        # This example is more restrictive, but may break functionality.  Adjust as needed.
        csp = "default-src 'self'; " \
              "script-src 'self'; " \
              "style-src 'self'; " \
              "img-src 'self' data:; " \
              "font-src 'self'; " \
              "connect-src 'self'; " \
              "media-src 'self'; " \
              "object-src 'none'; " \
              "base-uri 'self'; " \
              "form-action 'self';"  # Restrict form submissions

        # Add report-uri or report-to for CSP violation reporting (replace with your endpoint)
        # csp += "report-uri /csp-report;"  # Deprecated, but still supported
        # csp += "report-to csp-endpoint;" # Requires setting up a reporting endpoint

        response.headers['Content-Security-Policy'] = csp
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Cache-Control'] = 'no-store'  # Prevent caching of sensitive data
        return response

    configure_database(app)  # Call the database configuration function

def configure_database(app):
    """Configures the database connection and models."""
    try:
        engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
        Base = declarative_base()  # Define a base class for declarative models

        # Example model (replace with your actual models)
        class User(Base):
            __tablename__ = 'users'
            id = Column(Integer, primary_key=True)
            username = Column(String(50), unique=True, nullable=False)
            email = Column(String(120), unique=True, nullable=False)

            def __repr__(self):
                return f"<User(username='{self.username}', email='{self.email}')>"

        Base.metadata.create_all(engine)  # Create tables if they don't exist

        Session = sessionmaker(bind=engine)
        app.db_session = Session()  # Store the session in the app context

        # Example usage (add a user) - REMOVE IN PRODUCTION
        # with app.app_context():
        #     new_user = User(username='testuser', email='test@example.com')
        #     app.db_session.add(new_user)
        #     try:
        #         app.db_session.commit()
        #     except IntegrityError as e:
        #         app.db_session.rollback()
        #         logger.error(f"Error adding user (likely duplicate): {e}")
        #     except Exception as e:
        #         app.db_session.rollback()
        #         logger.error(f"Error adding user: {e}")

        # Enforce foreign key constraints in SQLite (if using SQLite)
        if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']:
            def _fk_pragma_on_connect(dbapi_con, connection_record):
                dbapi_con.execute('pragma foreign_keys=ON')
            event.listen(engine, 'connect', _fk_pragma_on_connect)


    except Exception as e:
        logger.error(f"Error connecting to the database: {e}")
        # Handle the error appropriately (e.g., log it, display an error message)
        # Consider exiting the application if the database connection is critical.
        raise  # Re-raise the exception to stop the app if necessary

    # Teardown context to close the database session
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        if hasattr(app, 'db_session'):
            app.db_session.remove()


# Example route (demonstrates secure response)
@app.route("/")
@limiter.limit("5/minute")  # Example rate limit for the home route
def hello_world():
    """
    A simple route that returns a secure response.
    """
    response = make_response("<h1>Hello, World!</h1>")
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Explicit content type
    return response


# Example route demonstrating input sanitization
@app.route("/greet")
def greet():
    """
    A route that greets the user, demonstrating input sanitization.
    """
    name = request.args.get("name", "World")

    # Sanitize the input to prevent XSS attacks
    safe_name = escape(name)

    response = make_response(f"<h1>Hello, {safe_name}!</h1>")
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response


# Example route demonstrating secure file handling (much improved)
@app.route("/upload", methods=['POST'])
@limiter.limit("2/minute")  # Example rate limit for uploads
def upload_file():
    """
    A more secure example of file upload handling.
    """
    if 'file' not in request.files:
        logger.warning("No file part in request")
        abort(400, "No file part")

    file = request.files['file']

    if file.filename == '':
        logger.warning("No selected file")
        abort(400, "No selected file")

    filename = secure_filename(file.filename)  # Robust filename sanitization
    if not filename:
        logger.warning("Invalid filename")
        abort(400, "Invalid filename")

    if not allowed_file(filename):
        logger.warning(f"File type not allowed: {filename}")
        abort(400, "File type not allowed")

    # Generate a random filename to prevent collisions and information leakage
    unique_filename = str(uuid.uuid4())  # Generate a UUID
    file_extension = os.path.splitext(filename)[1]
    random_filename = unique_filename + file_extension
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], random_filename)

    try:
        # Content-based file type validation
        file_content = file.read()
        file.seek(0)  # Reset file pointer after reading
        mime = magic.from_buffer(file_content, mime=True)
        if not validate_file_content(file_content, mime):
            logger.warning(f"Invalid file content for {filename} (MIME: {mime})")
            abort(400, "Invalid file content")

        # Malware scanning (ClamAV)
        if not scan_file_for_malware(filepath, file_content):
            logger.warning(f"Malware detected in {filename}")
            abort(400, "Malware detected")

        # Save the file
        file.save(filepath)
        logger.info(f"File uploaded successfully to {filepath}")
        return f"File uploaded successfully. Filename: {random_filename}", 200

    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        abort(500, "Error uploading file")

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files securely."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_content(file_content, mime):
    """
    Validates the file content using libmagic.  This is a crucial security step.
    """
    try:
        logger.info(f"Detected MIME type: {mime}")

        # Example: Only allow images and text files
        if mime.startswith('image/') or mime == 'text/plain' or mime == 'application/pdf':
            return True
        else:
            logger.warning(f"Rejected MIME type: {mime}")
            return False
    except Exception as e:
        logger.error(f"Error validating file content: {e}")
        return False

def scan_file_for_malware(filepath, file_content):
    """Scans the uploaded file for malware using ClamAV."""
    try:
        # Save the file temporarily for scanning
        # with open(filepath, 'wb') as f:
        #     f.write(file_content)

        # Run ClamAV scan (make sure ClamAV is installed and in the PATH)
        result = subprocess.run(['clamscan', '--no-summary', '--infected', '-'], input=file_content, capture_output=True, text=True)
        # result = subprocess.run(['clamscan', '--no-summary', '--infected', filepath], capture_output=True, text=True)
        output = result.stdout
        logger.info(f"ClamAV scan result: {output}")

        if "OK" in output:
            return True
        else:
            logger.warning(f"Malware detected by ClamAV: {output}")
            return False
    except FileNotFoundError:
        logger.error("ClamAV not found. Please install ClamAV.")
        return True  # Assume safe if ClamAV is not available (for development, but not production!)
    except Exception as e:
        logger.error(f"Error scanning file with ClamAV: {e}")
        return False

# Example CSP report endpoint (for testing and monitoring)
@app.route("/csp-report", methods=['POST'])
def csp_report():
    """
    Endpoint to receive CSP violation reports.  Log and monitor these reports!
    """
    report = request.get_json()
    logger.warning(f"CSP Violation Report: {report}")
    return "OK", 200

# Error handling
@app.errorhandler(400)
def bad_request(error):
    return f"<h1>Bad Request</h1><p>{error.description}</p>", 400

@app.errorhandler(500)
def internal_server_error(error):
    return "<h1>Internal Server Error</h1><p>An unexpected error occurred.</p>", 500

if __name__ == '__main__':
    configure_app(app)
    # Consider using a production WSGI server like Gunicorn or uWSGI
    app.run(debug=True, host="0.0.0.0", port=5000)

