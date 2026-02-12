import logging
import os
import uuid
import hashlib
from flask import Flask, request, send_from_directory, abort
import mysql.connector
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import PyPDF2  # Import PyPDF2 here

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration -  IMPORTANT:  Replace with your actual values and keep them SECRET!
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
DATABASE_HOST = os.environ.get('DATABASE_HOST', 'localhost')  # Get from environment
DATABASE_USER = os.environ.get('DATABASE_USER', 'your_db_user')
DATABASE_PASSWORD = os.environ.get('DATABASE_PASSWORD', 'your_db_password')
DATABASE_NAME = os.environ.get('DATABASE_NAME', 'your_db_name')

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure the upload folder exists

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)


# Database connection function
def get_db_connection():
    """Establishes a connection to the MySQL database."""
    try:
        connection = mysql.connector.connect(
            host=DATABASE_HOST,
            user=DATABASE_USER,
            password=DATABASE_PASSWORD,
            database=DATABASE_NAME
        )
        return connection
    except mysql.connector.Error as err:
        logger.error(f"Error connecting to database: {err}")
        return None


def allowed_file(filename):
    """Checks if the filename has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_secure_filename(filename):
    """Generates a secure filename using UUID and hashing to prevent filename collisions and path traversal."""
    _, ext = os.path.splitext(filename)
    unique_id = uuid.uuid4()
    hashed_id = hashlib.sha256(str(unique_id).encode()).hexdigest()
    return hashed_id + ext  # Keep the extension for proper file handling


def validate_pdf_content(filepath):
    """
    Validates PDF content to prevent malicious files.
    This is NOT a foolproof method and sandboxing is highly recommended for production environments.
    """
    try:
        with open(filepath, 'rb') as pdf_file:
            pdf_reader = PyPDF2.PdfReader(pdf_file)

            # Check PDF Header
            if not pdf_file.read(5) == b'%PDF-':
                raise ValueError("Invalid PDF header.")
            pdf_file.seek(0)  # Reset file pointer

            # Check for JavaScript (Basic)
            for page in pdf_reader.pages:
                if '/JS' in page:
                    raise ValueError("PDF contains JavaScript (potentially malicious).")

            # Check number of pages
            num_pages = len(pdf_reader.pages)
            if num_pages > 100:  # Example limit
                raise ValueError("PDF has too many pages.")

            # Basic object stream check (very limited)
            # This is just an example; more sophisticated analysis is needed
            for obj in pdf_reader.objects.values():
                if isinstance(obj, bytes) and b'/FlateDecode' in obj:
                    if len(obj) > 100000:  # Example limit
                        raise ValueError("Large object stream detected.")

            logger.info(f"PDF has {num_pages} pages.")
            return True  # PDF appears valid
    except (PyPDF2.errors.PdfReadError, FileNotFoundError, ValueError) as e:
        logger.error(f"Invalid PDF file: {e}")
        return False


@app.route('/upload', methods=['POST'])
@limiter.limit("5/minute")  # Example: Limit uploads to 5 per minute
def upload_pdf():
    """Handles PDF file uploads, saves the file securely, and stores the filepath in the database."""
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)  # Sanitize original filename
            secure_filename_generated = generate_secure_filename(filename)  # Generate secure filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename_generated)

            file.save(filepath)

            # Enhanced PDF Content Validation
            if not validate_pdf_content(filepath):
                os.remove(filepath)
                return "Invalid PDF file.", 400

            # Store filepath in the database
            connection = get_db_connection()
            if connection:
                cursor = connection.cursor()
                try:
                    query = "INSERT INTO pdf_files (filepath) VALUES (%s)"
                    cursor.execute(query, (filepath,))
                    connection.commit()
                    return "File uploaded and filepath saved successfully!", 201
                except mysql.connector.Error as err:
                    logger.error(f"Error inserting into database: {err}")
                    # Delete the file if database insertion fails to prevent orphaned files
                    os.remove(filepath)
                    return "Error saving filepath to database. File upload aborted.", 500
                finally:
                    cursor.close()
                    connection.close()
            else:
                # Delete the file if database connection fails to prevent orphaned files
                os.remove(filepath)
                return "Database connection failed. File upload aborted.", 500

        except Exception as e:
            logger.exception(f"An error occurred: {e}")
            return "An error occurred during file upload.", 500
    else:
        return "Invalid file type. Only PDF files are allowed.", 400


@app.route('/download/<filename>')
def download_pdf(filename):
    """Downloads a PDF file based on the filename stored in the database."""
    try:
        # Validate filename (example)
        if not (4 <= len(filename) <= 64 and filename.isalnum()):  # Example validation
            logger.warning(f"Invalid filename format: {filename}")
            return "Invalid filename.", 400

        # Retrieve filepath from the database
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            try:
                query = "SELECT filepath FROM pdf_files WHERE filepath = %s"  # Use exact match
                cursor.execute(query, (filename,))
                result = cursor.fetchone()

                if result:
                    filepath = result[0]
                    # Security:  Check if the filepath is within the allowed upload folder.
                    # This prevents path traversal vulnerabilities.
                    if os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
                        directory = os.path.dirname(filepath)
                        filename_only = os.path.basename(filepath)
                        return send_from_directory(directory, filename_only, as_attachment=True)
                    else:
                        logger.warning(f"Attempted access to file outside upload folder: {filepath}")
                        abort(403)  # Forbidden
                else:
                    return "File not found in database.", 404
            except mysql.connector.Error as err:
                logger.error(f"Error retrieving filepath from database: {err}")
                return "Error retrieving file information.", 500
            finally:
                cursor.close()
                connection.close()
        else:
            return "Database connection failed.", 500
    except Exception as e:
        logger.exception(f"An error occurred during download: {e}")
        return "An error occurred during file download.", 500


if __name__ == '__main__':
    app.run(debug=True)

