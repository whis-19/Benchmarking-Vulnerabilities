from flask import Flask, request, abort, RequestEntityTooLarge, Response
import os
import re
from werkzeug.utils import secure_filename
import uuid
import magic  # Added
import logging # Added
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a safe folder for file operations
UPLOAD_FOLDER = '/var/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the folder if it doesn't exist

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv'}

# Maximum file size (16MB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///files.db'  # Use SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
db = SQLAlchemy(app)

# Define the File model
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    unique_filename = db.Column(db.String(255), nullable=False)
    content_type = db.Column(db.String(100), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)  # Import datetime
    # Add other metadata fields as needed (e.g., user_id)

    def __repr__(self):
        return f"<File(filename='{self.filename}', unique_filename='{self.unique_filename}')>"

# Create the database tables (run this once)
with app.app_context():
    db.create_all()

def allowed_file(filename):
    """
    Check if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_allowed_content_type(filepath):
    """
    Check if the file content type is allowed.
    """
    try:
        mime = magic.Magic(mime=True)
        mimetype = mime.from_file(filepath)
        logging.info(f"Detected MIME type: {mimetype}") # Log the detected MIME type
        return mimetype == 'text/plain' or mimetype == 'application/pdf' or mimetype == 'text/csv'
    except Exception as e:
        logging.error(f"Error detecting MIME type: {e}")
        return False

def generate_unique_filename(filename):
    """
    Generate a unique filename using UUID.
    """
    extension = filename.rsplit('.', 1)[1].lower()
    unique_id = str(uuid.uuid4())
    return f"{unique_id}.{extension}"


@app.route('/open_file')
def open_file():
    """
    Get the file name from the request using 'file_name' and check if the file opens successfully
    in the given path from the current directory.

    :return: The file object if the file opens successfully, None otherwise.
    """
    filename = request.args.get('file_name')

    if not filename:
        logging.warning("No filename provided")
        return "Error: No filename provided", 400

    # Validate user input using secure_filename
    filename = secure_filename(filename)

    if not filename:
        logging.warning("Invalid filename after sanitization")
        return "Error: Invalid filename", 400

    # Check for directory separators
    if '/' in filename or '\\' in filename:
        logging.warning("Directory separators are not allowed")
        return "Error: Directory separators are not allowed", 400

    # Check for multiple dots
    if filename.count('.') > 1:
        logging.warning("Multiple dots are not allowed")
        return "Error: Multiple dots are not allowed", 400

    # Check allowed extensions
    if not allowed_file(filename):
        logging.warning(f"Invalid file extension: {filename}")
        return "Error: Invalid file extension", 400

    # Query the database for the file
    file_record = File.query.filter_by(filename=filename).first()

    if not file_record:
        logging.warning(f"File not found in database: {filename}")
        return "Error: File not found", 404

    unique_filename = file_record.unique_filename
    content_type = file_record.content_type

    # Construct the full file path within the safe folder
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

    # Normalize the path and check for ".." components
    normalized_path = os.path.normpath(filepath)
    if ".." in normalized_path:
        logging.warning("Path contains invalid components (..)")
        return "Error: Path contains invalid components", 400

    # Ensure the path is within the safe folder
    abs_path = os.path.abspath(normalized_path)
    if not abs_path.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        logging.warning("Path is outside the allowed directory")
        return "Error: Path is outside the allowed directory", 400

    try:
        f = open(normalized_path, 'r')  # Open in read mode
        # Process the file (e.g., read its contents)
        file_content = f.read()
        response_text = f"File content: {file_content}"
        response = Response(response_text, mimetype=content_type) # Set mimetype appropriately
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    except FileNotFoundError:
        logging.error(f"File not found: {normalized_path}")
        return "Error: File not found", 404
    except Exception as e:
        logging.exception(f"An error occurred: {str(e)}") # Use logging.exception to capture the stack trace
        return f"Error: An error occurred: {str(e)}", 500
    finally:
        if 'f' in locals() and f:
            f.close()  # Ensure the file is always closed

@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(error):
    logging.warning("Request Entity Too Large: File size exceeds limit")
    return "Error: File size exceeds the allowed limit (16MB)", 413


if __name__ == '__main__':
    app.run(debug=True)

