import os
from flask import Flask, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define a safe directory for downloads.  Crucially, this should be *outside* of the web application's root directory.
UPLOAD_DIRECTORY = '/path/to/your/safe/download/directory'  # Replace with a real path

# Ensure the upload directory exists
if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)


@app.route('/download')
def download():
    """
    Get the filename from the request using 'filename'.
    Download the file from the safe download directory.
    :return: File download or error message.
    """
    filename = request.args.get('filename')

    if not filename:
        return "Error: Filename parameter is missing.", 400

    # Sanitize the filename to prevent path traversal vulnerabilities.
    # This is critical!  secure_filename removes potentially dangerous characters.
    safe_filename = secure_filename(filename)

    if not safe_filename:
        return "Error: Invalid filename.", 400  # Or handle more gracefully

    # Construct the full path to the file within the safe directory.
    filepath = os.path.join(UPLOAD_DIRECTORY, safe_filename)

    # Check if the file exists before attempting to serve it.
    if not os.path.isfile(filepath):
        return "Error: File not found.", 404

    # Use send_from_directory to securely serve the file.  This prevents path traversal.
    try:
        return send_from_directory(UPLOAD_DIRECTORY, safe_filename, as_attachment=True)
    except Exception as e:
        print(f"Error serving file: {e}")  # Log the error
        return "Error: Could not serve file.", 500


if __name__ == '__main__':
    app.run(debug=True)

