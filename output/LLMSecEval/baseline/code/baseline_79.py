import os
import uuid
import hashlib
from flask import Flask, request, send_from_directory, abort
import mysql.connector
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration -  IMPORTANT:  Replace with your actual values!
UPLOAD_FOLDER = 'uploads'
DATABASE_HOST = 'localhost'
DATABASE_USER = 'your_db_user'
DATABASE_PASSWORD = 'your_db_password'
DATABASE_NAME = 'your_db_name'
ALLOWED_EXTENSIONS = {'pdf'}  # Restrict to PDF files only

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


def generate_secure_filename(filename):
    """Generates a secure and unique filename."""
    _, ext = os.path.splitext(filename)
    unique_id = uuid.uuid4()
    hashed_id = hashlib.sha256(str(unique_id).encode()).hexdigest()
    return f"{hashed_id}{ext}"


@app.route('/upload', methods=['POST'])
def upload_pdf():
    """Handles PDF file uploads, saves to disk, and stores the filepath in the database."""
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        try:
            # Generate a secure filename
            filename = secure_filename(file.filename)  # Sanitize original filename
            secure_filename_val = generate_secure_filename(filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename_val)

            # Save the file
            file.save(filepath)

            # Store the filepath in the database
            db = connect_to_db()
            if db:
                cursor = db.cursor()
                sql = "INSERT INTO pdf_files (filepath) VALUES (%s)"  # Assuming a table named 'pdf_files' with a 'filepath' column
                val = (filepath,)
                cursor.execute(sql, val)
                db.commit()
                cursor.close()
                db.close()

                return "File uploaded and filepath saved successfully!", 201  # 201 Created
            else:
                # Handle database connection error
                os.remove(filepath)  # Remove the uploaded file if DB connection fails
                return "Error: Could not connect to the database.", 500

        except Exception as e:
            # Handle any other errors during file saving or database interaction
            if os.path.exists(filepath):
                os.remove(filepath)  # Remove the uploaded file if an error occurs
            print(f"Error during upload: {e}")
            return f"Error during upload: {e}", 500

    else:
        return "Invalid file type. Only PDF files are allowed.", 400


@app.route('/download/<filename>')
def download_pdf(filename):
    """Downloads a PDF file from the uploads folder."""
    try:
        # Security:  Validate the filename against the database to prevent path traversal
        db = connect_to_db()
        if db:
            cursor = db.cursor()
            sql = "SELECT filepath FROM pdf_files WHERE filepath LIKE %s"  # Use LIKE for partial match
            val = (f"%{filename}",)  # Match any filepath containing the filename
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
        print(f"Error during download: {e}")
        abort(500)  # Internal Server Error


if __name__ == '__main__':
    app.run(debug=True)

