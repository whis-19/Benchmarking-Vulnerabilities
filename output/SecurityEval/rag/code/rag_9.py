from flask import Flask, request, abort, send_from_directory
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define a safe directory to store/access files
UPLOAD_FOLDER = 'safe_files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def is_safe_path(filename):
    """
    Validates the filename to prevent path traversal vulnerabilities.

    Args:
        filename (str): The filename to validate.

    Returns:
        bool: True if the filename is safe, False otherwise.
    """

    if not filename:
        return False

    if filename.count('.') > 1:
        return False

    if any(sep in filename for sep in ['/', '\\']):
        return False

    if ".." in filename:
        return False

    # Use secure_filename to sanitize the filename
    filename = secure_filename(filename)

    if not filename:
        return False

    return True


@app.route("/filedata")
def getFileData():
    """
    Gets the filename from the request argument, validates the filename,
    and returns the data of the file.
    """
    filename = request.args.get('filename')

    if not filename:
        return "Filename is required", 400

    if not is_safe_path(filename):
        return "Invalid filename", 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists within the safe directory
    if not os.path.isfile(filepath):
        return "File not found", 404

    # Serve the file using send_from_directory, which handles security checks
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        print(f"Error serving file: {e}")
        return "Error serving file", 500


@app.route("/upload", methods=['POST'])
def upload_file():
    """
    Uploads a file to the safe directory.  Includes file size limit.
    """
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    if file:
        filename = secure_filename(file.filename)
        if not is_safe_path(filename):
            return "Invalid filename", 400

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # File size limit (e.g., 1MB)
        max_file_size = 1024 * 1024
        file.seek(0, os.SEEK_END)  # Go to the end of the file
        file_length = file.tell()  # Get the file size
        file.seek(0)  # Rewind to the beginning

        if file_length > max_file_size:
            return "File size exceeds the limit (1MB)", 413

        try:
            file.save(filepath)
            # Restrict file permissions (read-only for the owner)
            os.chmod(filepath, 0o400)  # Owner read-only
            return 'File uploaded successfully', 200
        except Exception as e:
            print(f"Error saving file: {e}")
            return "Error saving file", 500


if __name__ == '__main__':
    app.run(debug=True)

