from flask import Flask, request, abort, send_from_directory
import os
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for session management if used

# Define allowed file extensions and directory
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv'}
UPLOAD_DIRECTORY = '/safe/file/storage'  # Replace with a safe directory outside web root
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True) # Ensure the directory exists

def is_safe_path(basedir, path, filename):
    """
    Safely checks if a path is within the allowed base directory and filename is safe.
    """
    filepath = os.path.join(basedir, path, filename)
    return os.path.abspath(filepath).startswith(basedir)

def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """
    Sanitizes the filename to prevent path traversal and other attacks.
    """
    # Remove any characters that are not alphanumeric, underscores, periods, or hyphens
    filename = re.sub(r'[^\w\._-]', '', filename)
    # Ensure the filename does not start with a period
    filename = filename.lstrip('.')
    return filename

@app.route("/filedata")
def getFileData():
    """
    Get the filename from the request argument, validate the filename,
    and return the data of the file.
    """
    filename = request.args.get('filename')

    if not filename:
        return "Filename is required", 400

    # Sanitize the filename
    filename = sanitize_filename(filename)

    # Validate the filename against allowed extensions
    if not allowed_file(filename):
        return "Invalid file type", 400

    # Construct the full file path
    filepath = os.path.join(UPLOAD_DIRECTORY, filename)

    # Prevent path traversal attacks
    if not is_safe_path(UPLOAD_DIRECTORY, "", filename):
        return "Invalid filename", 400

    try:
        # Serve the file using send_from_directory (more secure than reading the file directly)
        return send_from_directory(UPLOAD_DIRECTORY, filename, as_attachment=True)
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        print(f"Error serving file: {e}") # Log the error
        return "Internal Server Error", 500

# Example route to upload files (for testing purposes, remove in production if not needed)
@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Upload a file to the server.
    """
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file and allowed_file(file.filename):
        filename = sanitize_filename(file.filename)
        filepath = os.path.join(UPLOAD_DIRECTORY, filename)
        file.save(filepath)
        return 'File uploaded successfully'
    else:
        return 'Invalid file type', 400

# Example usage (for testing)
if __name__ == '__main__':
    #  Never use 'debug=True' in a production environment.
    app.run(debug=False, host='0.0.0.0', port=5000)

