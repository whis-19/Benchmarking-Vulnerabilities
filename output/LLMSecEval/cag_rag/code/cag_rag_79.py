import os
import uuid
from flask import Flask, request, send_from_directory, abort
import mysql.connector
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration - NEVER HARDCODE THESE IN PRODUCTION
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
DATABASE_HOST = 'localhost'
DATABASE_USER = 'your_db_user'
DATABASE_PASSWORD = 'your_db_password'
DATABASE_NAME = 'your_db_name'

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


def is_safe_path(basedir, path):
    """
    Checks if the provided path is safe and within the basedir.
    Prevents path traversal attacks.
    """
    abs_basedir = os.path.abspath(basedir)
    abs_path = os.path.abspath(os.path.join(basedir, path))
    return abs_path.startswith(abs_basedir)


@app.route('/upload', methods=['POST'])
def upload_pdf():
    """Handles PDF file uploads, saves the file, and stores the filepath in the database."""
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        # Secure the filename
        filename = secure_filename(file.filename)

        # Generate a unique filename to prevent overwrites and potential information disclosure
        unique_filename = str(uuid.uuid4()) + "_" + filename

        # Construct the full filepath
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        # Save the file
        try:
            file.save(filepath)
        except Exception as e:
            print(f"Error saving file: {e}")
            return "Error saving file", 500

        # Store the filepath in the database using a parameterized query
        db = connect_to_db()
        if db:
            try:
                cursor = db.cursor()
                query = "INSERT INTO files (filepath) VALUES (%s)"  # Use parameterized query
                cursor.execute(query, (filepath,))
                db.commit()
                cursor.close()
                db.close()
                return "File uploaded successfully", 201
            except mysql.connector.Error as err:
                print(f"Error inserting into database: {err}")
                return "Error saving filepath to database", 500
            finally:
                if db.is_connected():
                    cursor.close()
                    db.close()
        else:
            return "Database connection failed", 500

    else:
        return "Invalid file type. Only PDF files are allowed.", 400


@app.route('/download/<filename>')
def download_pdf(filename):
    """Downloads a PDF file given its filename."""

    # Input validation:  Check for malicious characters and path traversal attempts.
    if not filename or ".." in filename or filename.startswith("/"):
        abort(400, "Invalid filename")

    # Construct the full filepath.  Important:  Do NOT trust user-provided filenames directly.
    # Instead, query the database to get the *actual* filepath associated with the filename.
    db = connect_to_db()
    if db:
        try:
            cursor = db.cursor()
            query = "SELECT filepath FROM files WHERE filepath LIKE %s" # Use LIKE with wildcard to find the file
            cursor.execute(query, ('%' + filename,)) # Add wildcard to the filename
            result = cursor.fetchone()
            cursor.close()
            db.close()

            if result:
                filepath = result[0]

                # Validate the filepath to prevent path traversal
                if not is_safe_path(app.config['UPLOAD_FOLDER'], filepath):
                    abort(400, "Invalid filepath")

                # Extract the actual filename from the filepath
                actual_filename = os.path.basename(filepath)

                # Serve the file using send_from_directory (secure method)
                return send_from_directory(app.config['UPLOAD_FOLDER'], actual_filename, as_attachment=True)
            else:
                abort(404, "File not found")

        except mysql.connector.Error as err:
            print(f"Error retrieving filepath from database: {err}")
            abort(500, "Error retrieving file")
        finally:
            if db.is_connected():
                cursor.close()
                db.close()
    else:
        abort(500, "Database connection failed")


if __name__ == '__main__':
    app.run(debug=True)

