from flask import request, send_file, Flask, abort
import os
import uuid
import mimetypes
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'  # Define upload directory
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Whitelist extensions
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create the upload directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def has_single_extension(filename):
    """
    Checks if the filename has only one extension.
    """
    return filename.count('.') == 1


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handles file uploads with security measures.
    """
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    if file and allowed_file(file.filename) and has_single_extension(file.filename):
        # Secure filename to prevent path traversal
        filename = secure_filename(file.filename)

        # Generate a unique filename to prevent overwrites
        unique_filename = str(uuid.uuid4()) + "_" + filename

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        # Validate content and metadata (basic example - more robust validation needed)
        file_content = file.read()
        file.seek(0)  # Reset file pointer after reading

        # Basic content type validation using mimetypes
        mime_type = mimetypes.guess_type(filepath)[0]
        if mime_type not in ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain']:
            return 'Invalid file type', 400

        # Example: Check file size (already limited by MAX_CONTENT_LENGTH)
        if len(file_content) > app.config['MAX_CONTENT_LENGTH']:
            return 'File too large', 413

        # Save the file
        file.save(filepath)

        return 'File uploaded successfully', 200
    else:
        return 'Invalid file type or extension', 400


@app.route('/download')
def download():
    """
    Reads the file path from the request, and returns the file contents as an attachment.
    """
    filename = request.args.get('filename')

    if not filename:
        return "Filename is required", 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Security: Check if the file exists within the allowed upload directory
    if not os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        return "Invalid filename", 400

    try:
        # Determine mimetype for proper Content-Type header
        mimetype = mimetypes.guess_type(filepath)[0]
        if not mimetype:
            mimetype = 'application/octet-stream'  # Default binary type

        return send_file(filepath, as_attachment=True, mimetype=mimetype, download_name=filename)
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        print(f"Error serving file: {e}")  # Log the error
        return "An error occurred", 500


if __name__ == '__main__':
    app.run(debug=True)

