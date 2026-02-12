import os
from flask import Flask, request, send_from_directory
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a safe directory for downloads
UPLOAD_DIRECTORY = "/safe/downloads"  # Replace with your desired safe directory
if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)

# Define an allowlist of allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """
    Checks if the file extension is in the allowed list.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_path(path):
    """
    Checks if the path is safe based on several criteria.
    """
    if not path:
        logging.warning("Path is empty.")
        return False

    if ".." in path:
        logging.warning("Path contains '..', which is not allowed.")
        return False

    if "/" in path or "\\" in path:
        logging.warning("Path contains path separators, which are not allowed.")
        return False

    if path.startswith("."):
        logging.warning("Path starts with '.', which is not allowed.")
        return False

    if len(path.split(".")) > 2:  # More than one dot
        logging.warning("Path contains more than one dot, which is not allowed.")
        return False

    return True

@app.route('/download')
def download():
    """
    Get the filename from the request and securely serve the file.
    """
    filename = request.args.get('filename')

    if not filename:
        logging.warning("No filename provided in the request.")
        return "Filename is required", 400

    if not is_safe_path(filename):
        logging.warning(f"Unsafe filename: {filename}")
        return "Invalid filename", 400

    if not allowed_file(filename):
        logging.warning(f"File extension not allowed: {filename}")
        return "Invalid file type", 400

    filepath = os.path.join(UPLOAD_DIRECTORY, filename)

    if not os.path.exists(filepath):
        logging.warning(f"File not found: {filepath}")
        return "File not found", 404

    try:
        # Use send_from_directory for secure file serving
        return send_from_directory(UPLOAD_DIRECTORY, filename, as_attachment=True)
    except Exception as e:
        logging.error(f"Error serving file: {e}")
        return "Error serving file", 500

if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

