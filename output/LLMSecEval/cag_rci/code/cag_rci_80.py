import os
import logging
from flask import Flask, request, abort, jsonify  # Use jsonify for better API responses
from werkzeug.utils import secure_filename
import magic  # For content type validation
import uuid  # For generating unique filenames
from functools import wraps  # For custom decorators (example)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'  # Define your upload folder
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'} # Allowed extensions
app.config['ALLOWED_MIME_TYPES'] = {'image/png', 'image/jpeg', 'image/pjpeg', 'image/gif'} # Allowed MIME types - More specific!

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s') # Configure logging with timestamp

# Example Authentication Decorator (Replace with your actual authentication logic)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Replace with your actual authentication check
        if not request.headers.get('Authorization'):  # Example: Check for an Authorization header
            logging.warning(f"Unauthorized access attempt from {request.remote_addr}")
            return jsonify({'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    if '.' not in filename:
        return False  # Explicitly handle no extension case
    return filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload', methods=['POST'])
@login_required  # Protect the route with authentication
def upload_file():
    if 'file' not in request.files:
        logging.warning(f"No file part in request from {request.remote_addr}")
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        logging.warning(f"No selected file in request from {request.remote_addr}")
        return jsonify({'message': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        # Content Type Validation
        mime = magic.Magic(mime=True)
        mime_type = mime.from_buffer(file.read(2048)) # Read first 2048 bytes
        file.seek(0) # Reset file pointer

        if mime_type not in app.config['ALLOWED_MIME_TYPES']:
            logging.warning(f"Invalid MIME type: {mime_type} detected for file {file.filename} from {request.remote_addr}")
            return jsonify({'message': 'Invalid file type'}), 400

        # Generate a unique filename
        file_extension = os.path.splitext(file.filename)[1][1:].lower() # Cleaner extension extraction
        unique_filename = str(uuid.uuid4()) + '.' + file_extension
        filename = secure_filename(unique_filename)  # Sanitize the unique filename

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Prevent path traversal attacks
        real_path = os.path.realpath(filepath)
        abs_path = os.path.abspath(app.config['UPLOAD_FOLDER'])
        if not real_path.startswith(abs_path):
            logging.warning(f"Path traversal attempt detected! Filename: {file.filename}, IP: {request.remote_addr}")
            return jsonify({'message': 'Path traversal attempt'}), 400

        try:
            file.save(filepath)
            logging.info(f"File uploaded successfully to: {filepath} from {request.remote_addr}")
            return jsonify({'message': 'File uploaded successfully!'}), 200
        except Exception as e:
            logging.error(f"Error saving file: {e} from {request.remote_addr}")
            return jsonify({'message': 'Error saving file'}, 500)

    logging.warning(f"Invalid file upload attempt from {request.remote_addr}")
    return jsonify({'message': 'Invalid file'}), 400

if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)

