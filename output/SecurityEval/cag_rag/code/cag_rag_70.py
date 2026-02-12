import re
import os
from flask import request, Flask, abort, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration - should be externalized in a real application
UPLOAD_FOLDER = 'uploads'  # Define the upload directory
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max-limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handles file uploads, ensuring security.
    """
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part', 400

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file', 400

        username = request.args.get('username')  # Get username from request arguments
        if not username:
            return 'Username is required', 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)  # Sanitize filename
            if not re.search(username, filename, re.IGNORECASE):
                return 'Username not found in filename', 400

            # Construct the full file path
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Prevent path traversal attacks by canonicalizing the path
            filepath = os.path.abspath(filepath)
            if not filepath.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
                return 'Invalid file path', 400

            try:
                file.save(filepath)
                return 'File uploaded successfully', 200
            except Exception as e:
                print(f"Error saving file: {e}")  # Log the error
                return 'Error uploading file', 500
        else:
            return 'Invalid file type', 400


@app.route('/files/<filename>')
def download_file(filename):
    """
    Securely serves files from the upload directory.
    """
    try:
        # Sanitize filename
        filename = secure_filename(filename)

        # Construct the full file path
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Prevent path traversal attacks by canonicalizing the path
        filepath = os.path.abspath(filepath)
        if not filepath.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
            abort(400)  # or return 'Invalid file path', 400

        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        abort(404)


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server.
    app.run(debug=True, host='0.0.0.0', port=5000)

