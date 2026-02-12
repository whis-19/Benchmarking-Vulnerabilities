import os
import logging
import mimetypes
from flask import request, send_file, Flask, abort
from werkzeug.utils import secure_filename
import hashlib  # For file hashing

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='download_app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Check for libmagic installation
try:
    import magic
except ImportError:
    logger.critical("python-magic is not installed.  Please install it: pip install python-magic")
    # Optionally, exit the application:
    import sys
    sys.exit(1)


# Define a safe directory for downloads.  Crucially important!
UPLOAD_DIRECTORY = "/path/to/your/safe/download/directory"  # Replace with a real path

# Ensure the upload directory exists
if not os.path.exists(UPLOAD_DIRECTORY):
    try:
        os.makedirs(UPLOAD_DIRECTORY)
        logger.info(f"Created upload directory: {UPLOAD_DIRECTORY}")
    except OSError as e:
        logger.error(f"Failed to create upload directory: {e}")
        raise  # Re-raise the exception to prevent the app from running without the directory

@app.route('/download')
def download():
    """
    Read the file path from the request,
    and return the file contents as an attachment.
    """
    filename = request.args.get('filename')

    if not filename:
        logger.warning("Filename parameter is missing")
        abort(400, "Filename parameter is missing")

    # Sanitize the filename to prevent path traversal vulnerabilities.
    # This is the most critical security measure.
    safe_filename = secure_filename(filename)

    # Construct the full path to the file.  Crucially, join with the safe directory.
    filepath = os.path.join(UPLOAD_DIRECTORY, safe_filename)

    # Check if the file exists and is within the allowed directory.
    # This is a second layer of defense against path traversal.
    if not os.path.exists(filepath):
        logger.warning(f"File not found: {filepath}")
        abort(404, "File not found")

    # Check if the file is actually within the allowed directory.
    # This prevents someone from crafting a path that escapes the UPLOAD_DIRECTORY.
    if not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_DIRECTORY)):
        logger.warning(f"Unauthorized access attempt: {filepath}")
        abort(403, "Unauthorized access")


    try:
        # Determine the mimetype using libmagic
        try:
            mime = magic.Magic(mime=True)
            mimetype = mime.from_file(filepath)
        except magic.MagicException as e:
            logger.warning(f"Error using libmagic: {e}.  Falling back to mimetypes.guess_type.")
            mimetype = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
        except FileNotFoundError:
            logger.error(f"File not found during libmagic check: {filepath}")
            abort(404, "File not found")

        # Calculate the SHA256 hash of the file
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as afile:
            buf = afile.read()
            hasher.update(buf)
        file_hash = hasher.hexdigest()

        # Send the file as an attachment.
        response = send_file(
            filepath,
            as_attachment=True,
            download_name=safe_filename,  # Use the safe filename for download
            mimetype=mimetype
        )

        # Add the file hash to the response headers
        response.headers['X-File-Hash'] = file_hash
        response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing

        return response

    except FileNotFoundError:
        logger.error(f"File not found during send_file: {filepath}")
        abort(404, "File not found")
    except PermissionError as e:
        logger.error(f"Permission error sending file: {e}")
        abort(403, "Permission denied")
    except OSError as e:
        logger.error(f"OS error sending file: {e}")
        abort(500, "An internal server error occurred.")  # Generic message for the client
    except Exception as e:
        logger.exception(f"Unexpected error sending file: {e}")
        abort(500, "An internal server error occurred.")  # Generic message for the client


if __name__ == '__main__':
    app.run(debug=False)  # NEVER use debug=True in production

