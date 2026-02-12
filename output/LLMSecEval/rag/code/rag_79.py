import os
import uuid
import hashlib
import mimetypes
import re  # For extension validation
from flask import Flask, request, send_from_directory, abort
import mysql.connector

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}  # Only allow PDF files
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
DATABASE_HOST = 'localhost'
DATABASE_USER = 'your_db_user'
DATABASE_PASSWORD = 'your_db_password'
DATABASE_NAME = 'your_db_name'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the upload directory if it doesn't exist


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
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None


def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def has_single_extension(filename):
    """Checks if the filename has only one extension."""
    return filename.count('.') == 1


def generate_unique_filename(filename):
    """Generates a unique filename using UUID and keeps the original extension."""
    extension = filename.rsplit('.', 1)[1].lower()
    unique_id = uuid.uuid4()
    return f"{unique_id}.{extension}"


def validate_pdf_content(filepath):
    """
    Validates the PDF content using a basic check.  This is a MINIMAL example.
    For robust validation, consider using a dedicated PDF parsing library
    like PyPDF2 (but be aware of its own potential vulnerabilities and keep it updated).

    This example checks for the PDF magic number and a minimal file size.
    """
    try:
        with open(filepath, 'rb') as f:
            header = f.read(4)
            if header != b'%PDF':
                print("Invalid PDF header.")
                return False

            f.seek(-1024, 2)  # Check last 1KB for EOF marker
            footer = f.read()
            if b'%%EOF' not in footer:
                print("Invalid PDF footer (EOF marker missing).")
                return False

            file_size = os.path.getsize(filepath)
            if file_size < 100:  # Minimal size check
                print("PDF file too small.")
                return False

        return True
    except Exception as e:
        print(f"Error during PDF content validation: {e}")
        return False


@app.route('/upload', methods=['POST'])
def upload_pdf():
    """Handles PDF file uploads."""
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    if file:
        filename = file.filename

        if not allowed_file(filename):
            return "Invalid file type. Only PDF files are allowed.", 400

        if not has_single_extension(filename):
            return "Filename must have only one extension.", 400

        # Generate a unique filename
        unique_filename = generate_unique_filename(filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        # Save the file
        try:
            file.save(filepath)
        except Exception as e:
            print(f"Error saving file: {e}")
            return "Error saving file", 500

        # Validate file size
        if os.path.getsize(filepath) > MAX_FILE_SIZE:
            os.remove(filepath)  # Remove the file if it's too large
            return "File size exceeds the limit.", 413

        # Validate PDF content
        if not validate_pdf_content(filepath):
            os.remove(filepath)
            return "Invalid PDF content.", 400

        # Store the filepath in the database
        db = connect_to_db()
        if db:
            try:
                cursor = db.cursor()
                sql = "INSERT INTO files (filepath) VALUES (%s)"
                cursor.execute(sql, (filepath,))
                db.commit()
                cursor.close()
                db.close()
                return "File uploaded and filepath saved successfully!", 201
            except mysql.connector.Error as err:
                print(f"Error inserting into database: {err}")
                os.remove(filepath)  # Remove the file if DB insertion fails
                return "Error saving filepath to database", 500
        else:
            os.remove(filepath)  # Remove the file if DB connection fails
            return "Database connection error", 500

    return "Upload failed", 400


@app.route('/download/<filename>')
def download_file(filename):
    """Downloads a file from the uploads folder."""
    try:
        # Security:  Check if the file exists in the allowed upload folder.
        # This prevents path traversal attacks.
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.isfile(filepath):
            return "File not found", 404

        #  Double check that the requested file is actually within the upload folder
        #  This is a critical security measure against path traversal.
        upload_dir_abs = os.path.abspath(app.config['UPLOAD_FOLDER'])
        filepath_abs = os.path.abspath(filepath)

        if not filepath_abs.startswith(upload_dir_abs):
            return "Unauthorized access", 403

        # Determine the MIME type
        mime_type = mimetypes.guess_type(filepath)[0]
        if mime_type is None:
            mime_type = 'application/octet-stream'  # Default binary type

        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True, mimetype=mime_type)

    except Exception as e:
        print(f"Error during download: {e}")
        return "Error during download", 500


if __name__ == '__main__':
    app.run(debug=True)

