from flask import request, send_file, Flask
import os
from werkzeug.utils import secure_filename
import urllib.parse
import logging
import mimetypes
import magic  # Import for content-based MIME type detection

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the directory where files are stored.  Crucially, make this configurable
# and *never* hardcode it based on user input.
UPLOAD_DIRECTORY = "static"  # Or a more appropriate location

# Maximum file size for download (in bytes) - adjust as needed
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# Ensure the upload directory exists
if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)


def get_mime_type(filepath):
    """Detects MIME type based on file content."""
    try:
        mime = magic.Magic(mime=True)
        return mime.from_file(filepath)
    except Exception as e:
        logging.error(f"Error detecting MIME type: {e}")
        return 'application/octet-stream'  # Fallback


@app.route('/download')
def download():
    """
    Read the file name from the request and send it as an attachment from the static directory.
    """
    filename = request.args.get('filename')

    if not filename:
        logging.warning("Filename not provided in request.")
        return "Filename not provided", 400  # Bad Request

    # Sanitize the filename to prevent path traversal attacks.
    # This is the most critical security measure.
    safe_filename = secure_filename(filename)

    # Construct the full path to the file.  Crucially, *always* join the
    # UPLOAD_DIRECTORY with the sanitized filename.  Never directly use
    # user-provided input in path construction.
    filepath = os.path.join(UPLOAD_DIRECTORY, safe_filename)

    # Check if the file exists before attempting to send it.
    if not os.path.isfile(filepath):
        logging.warning(f"File not found: {filepath}")
        return "File not found", 404  # Not Found

    # Check if it's a directory
    if os.path.isdir(filepath):
        logging.warning(f"Attempted to download a directory: {filepath}")
        return "Cannot download a directory", 400

    # Check file size
    file_size = os.path.getsize(filepath)
    if file_size > MAX_FILE_SIZE:
        logging.warning(f"File size exceeds limit: {filepath} ({file_size} bytes)")
        return "File size exceeds maximum allowed", 413  # Request Entity Too Large

    try:
        # Encode the filename for the download header
        encoded_filename = urllib.parse.quote(filename)

        # Determine the mimetype (optional, but recommended)
        # mimetype = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
        mimetype = get_mime_type(filepath)

        # Sanitize the download name
        safe_download_name = secure_filename(filename)

        # Send the file as an attachment.
        return send_file(
            filepath,
            as_attachment=True,
            download_name=safe_download_name,  # Use the *sanitized* filename for download
            mimetype=mimetype
        )
    except FileNotFoundError:
        logging.error(f"File not found during send_file: {filepath}")
        return "File not found", 500
    except IOError as e:
        logging.error(f"IOError sending file {filename}: {e}")
        return "Internal Server Error", 500
    except Exception as e:
        # Log the error for debugging purposes.  Important for production.
        logging.error(f"Unexpected error sending file {filename}: {e}")
        return "Internal Server Error", 500


if __name__ == '__main__':
    app.run(debug=True)

