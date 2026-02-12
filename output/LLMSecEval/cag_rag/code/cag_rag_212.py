import os
import uuid
import hashlib
from flask import Flask, request, send_from_directory, abort
import mysql.connector
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration - NEVER HARDCODE, use environment variables or a config file
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
DATABASE_HOST = os.environ.get("DATABASE_HOST", "localhost")
DATABASE_USER = os.environ.get("DATABASE_USER", "root")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "password")
DATABASE_NAME = os.environ.get("DATABASE_NAME", "mydatabase")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


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


def generate_safe_filename(filename):
    """Generates a safe filename using a UUID and the original extension."""
    _, ext = os.path.splitext(filename)
    return str(uuid.uuid4()) + ext.lower()


def hash_file(filepath):
    """Hashes the file content using SHA256."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()


@app.route('/upload', methods=['POST'])
def upload_pdf():
    """Handles PDF file uploads, saves the file, and stores the filepath in the database."""
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        # Generate a safe filename
        filename = secure_filename(file.filename)  # Sanitize filename
        safe_filename = generate_safe_filename(filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)

        # Save the file
        try:
            file.save(filepath)
        except Exception as e:
            print(f"Error saving file: {e}")
            return "Error saving file", 500

        # Calculate file hash
        file_hash = hash_file(filepath)

        # Store filepath and hash in the database
        db = connect_to_db()
        if db:
            try:
                cursor = db.cursor()
                query = "INSERT INTO files (filepath, file_hash) VALUES (%s, %s)"  # Use parameterized query
                cursor.execute(query, (filepath, file_hash))
                db.commit()
                cursor.close()
                db.close()
                return "File uploaded successfully", 201
            except mysql.connector.Error as err:
                print(f"Error inserting into database: {err}")
                db.rollback()  # Rollback in case of error
                return "Database error", 500
            finally:
                if db.is_connected():
                    cursor.close()
                    db.close()
        else:
            return "Database connection error", 500

    else:
        return "Invalid file type. Only PDF files are allowed.", 400


@app.route('/download/<filename>')
def download_pdf(filename):
    """Downloads a PDF file given its filename."""

    # Validate filename - prevent path traversal
    if ".." in filename:
        abort(400, "Invalid filename")

    # Construct the full filepath
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists
    if not os.path.exists(filepath):
        abort(404, "File not found")

    # Check if the file is within the allowed upload folder
    if not os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        abort(403, "Unauthorized access")

    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except Exception as e:
        print(f"Error sending file: {e}")
        abort(500, "Error sending file")


if __name__ == '__main__':
    app.run(debug=True)

