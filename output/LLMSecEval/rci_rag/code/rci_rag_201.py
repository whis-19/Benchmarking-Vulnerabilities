import os
import uuid
import magic  # Requires: pip install python-magic
from flask import Flask, request, send_from_directory, abort
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/img')
def img():
    filename = request.args.get('file')

    if not filename:
        return "Filename parameter is missing", 400

    filename = secure_filename(filename) # Sanitize filename

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    abs_path = os.path.abspath(filepath)
    upload_folder_abs = os.path.abspath(app.config['UPLOAD_FOLDER'])

    if not abs_path.startswith(upload_folder_abs):
        return "Invalid filename (path traversal attempt)", 400

    if not os.path.exists(filepath):
        return "File not found", 404

    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        logging.exception("Error serving file:")  # Log the full exception
        return "An error occurred", 500


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles file uploads, ensuring security."""
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = str(uuid.uuid4()) + '.' + ext  # Generate a unique filename
        filename = secure_filename(filename) # Sanitize the unique filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            # Check file size before saving
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)  # Reset file pointer to the beginning

            if file_size > MAX_FILE_SIZE:
                return "File size exceeds the limit", 413

            file.save(filepath)  # Save the file first

            # Content type validation using libmagic
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(filepath)
            if mime_type not in ['image/jpeg', 'image/png', 'image/gif']:
                os.remove(filepath)  # Remove the file if it's invalid
                return "Invalid content type", 400

            return 'File uploaded successfully', 200
        except Exception as e:
            logging.exception("Error uploading file:") # Log the full exception
            if os.path.exists(filepath):
                os.remove(filepath) # Remove potentially harmful file
            return "Error uploading file", 500
    else:
        return 'Invalid file type', 400

if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)

