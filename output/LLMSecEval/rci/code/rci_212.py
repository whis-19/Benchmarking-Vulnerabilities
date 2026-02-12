import os
import uuid
import hashlib
from flask import Flask, request, send_from_directory, abort
import mysql.connector
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re  # Import re
import logging # Import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration -  IMPORTANT:  Replace with your actual values!
UPLOAD_FOLDER = 'uploads'
# DATABASE_HOST = 'localhost' # Removed hardcoded value
# DATABASE_USER = 'your_db_user' # Removed hardcoded value
# DATABASE_PASSWORD = 'your_db_password' # Removed hardcoded value
# DATABASE_NAME = 'your_db_name' # Removed hardcoded value

DATABASE_HOST = os.environ.get('DATABASE_HOST', 'localhost')  # Default to localhost
DATABASE_USER = os.environ.get('DATABASE_USER')
DATABASE_PASSWORD = os.environ.get('DATABASE_PASSWORD')
DATABASE_NAME = os.environ.get('DATABASE_NAME')

if not all([DATABASE_USER, DATABASE_PASSWORD, DATABASE_NAME]):
    raise ValueError("Database credentials not set in environment variables.")


ALLOWED_EXTENSIONS = {'pdf'}  # Restrict to PDF files only
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Adjust limits as needed
)


def connect_to_db():
    """Connects to the MySQL database."""
    try:
        db = mysql.connector.connect(
            host=DATABASE_HOST,
            user=DATABASE_USER,
            password=DATABASE_PASSWORD,
            database=DATABASE_NAME
        )
        return db
    except mysql.connector.errors.ProgrammingError as err:
        logging.error(f"SQL Syntax Error: {err}")
        return None
    except mysql.connector.errors.InterfaceError as err:
        logging.error(f"Database Connection Error: {err}")
        return None
    except mysql.connector.Error as err:
        logging.error(f"General Database Error: {err}")
        return None


def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_secure_filename(filename):
    """Generates a secure and unique filename."""
    _, ext = os.path.splitext(filename)
    unique_id = uuid.uuid4()
    hashed_id = hashlib.sha256(str(unique_id).encode()).hexdigest()
    return f"{hashed_id}{ext}"


def sanitize_filename(filename):
    """More robust filename sanitization using regular expressions."""
    # Allow only alphanumeric characters, underscores, hyphens, and dots
    sanitized_filename = re.sub(r"[^a-zA-Z0-9_.-]", "", filename)
    return sanitized_filename

def generate_unique_filename(filename, upload_folder):
    """Generates a unique filename, retrying if necessary."""
    max_retries = 5
    for i in range(max_retries):
        secure_filename_val = generate_secure_filename(filename)
        filepath = os.path.join(upload_folder, secure_filename_val)
        if not os.path.exists(filepath):
            return secure_filename_val, filepath
        logging.warning(f"Filename collision detected, retrying ({i+1}/{max_retries})")
    raise Exception("Could not generate a unique filename after multiple retries.")


@app.route('/upload', methods=['POST'])
@limiter.limit("5 per hour")  # Limit uploads to 5 per hour
def upload_pdf():
    """Handles PDF file uploads, saves to disk, and stores the filepath in the database."""
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename) and file.content_type == 'application/pdf':
        try:
            # Generate a secure filename
            filename = secure_filename(file.filename)  # Sanitize original filename
            filename = sanitize_filename(filename) # More robust sanitization
            secure_filename_val, filepath = generate_unique_filename(filename, app.config['UPLOAD_FOLDER'])

            # Save the file
            file.save(filepath)

            # Store the filepath in the database
            db = connect_to_db()
            if db:
                cursor = db.cursor()
                sql = "INSERT INTO pdf_files (filepath, filename) VALUES (%s, %s)"  # Assuming a table named 'pdf_files' with a 'filepath' column
                val = (filepath, secure_filename_val)
                cursor.execute(sql, val)
                db.commit()
                cursor.close()
                db.close()

                return "File uploaded and filepath saved successfully!", 201  # 201 Created
            else:
                # Handle database connection error
                try:
                    os.remove(filepath)  # Remove the uploaded file if DB connection fails
                except OSError as e:
                    logging.error(f"Error deleting file: {e}")
                return "Error: Could not connect to the database.", 500

        except Exception as e:
            # Handle any other errors during file saving or database interaction
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)  # Remove the uploaded file if an error occurs
                except OSError as e:
                    logging.error(f"Error deleting file: {e}")
            logging.error(f"Error during upload: {e}")
            return f"Error during upload: {e}", 500

    else:
        return "Invalid file type or content type. Only PDF files are allowed.", 400


@app.route('/download/<filename>')
@limiter.limit("10 per minute") # Limit downloads to 10 per minute
def download_pdf(filename):
    """Downloads a PDF file from the uploads folder."""
    try:
        # Security:  Validate the filename against the database to prevent path traversal
        db = connect_to_db()
        if db:
            cursor = db.cursor()
            sql = "SELECT filepath FROM pdf_files WHERE filename = %s"  # Use exact match
            val = (filename,)
            cursor.execute(sql, val)
            result = cursor.fetchone()
            cursor.close()
            db.close()

            if result:
                filepath = result[0]
                # Extract the actual filename from the filepath
                actual_filename = os.path.basename(filepath)

                # Security: Double-check that the requested filename matches the actual filename
                if actual_filename == filename:
                    # Additional validation of filepath
                    if not filepath.startswith(app.config['UPLOAD_FOLDER']):
                        logging.warning(f"Attempted access outside of UPLOAD_FOLDER: {filepath}")
                        abort(403)  # Forbidden

                    return send_from_directory(app.config['UPLOAD_FOLDER'],
                                               actual_filename,
                                               as_attachment=True)
                else:
                    abort(404)  # Not Found - Filename mismatch
            else:
                abort(404)  # Not Found - File not in database
        else:
            abort(500)  # Internal Server Error - Database connection failed

    except Exception as e:
        logging.error(f"Error during download: {e}")
        abort(500)  # Internal Server Error


if __name__ == '__main__':
    app.run(debug=False) # Changed to debug=False

