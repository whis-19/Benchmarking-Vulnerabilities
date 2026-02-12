from flask import request, send_file, Flask, abort
import os
import logging
from werkzeug.utils import safe_join
import mimetypes  # For MIME type detection

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a safe directory for downloads (outside the web root)
UPLOAD_FOLDER = '/safe/download/directory'  # Replace with your desired path
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed file extensions
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.jpg', '.jpeg', '.png'}

# Maximum filename length
MAX_FILENAME_LENGTH = 255

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def is_safe_filename(filename):
    """
    Validates the filename based on stringent allowlist and extension check.
    """
    if not isinstance(filename, str):
        logging.warning(f"Filename is not a string: {filename}")
        return False

    if len(filename) > MAX_FILENAME_LENGTH:
        logging.warning(f"Filename exceeds maximum length: {filename}")
        return False

    if not filename.isalnum():
        logging.warning(f"Filename contains non-alphanumeric characters: {filename}")
        return False

    if '/' in filename or '\\' in filename:
        logging.warning(f"Filename contains directory separators: {filename}")
        return False

    if filename.count('.') > 1:
        logging.warning(f"Filename contains multiple dots: {filename}")
        return False

    # Check file extension
    _, ext = os.path.splitext(filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        logging.warning(f"Filename has an invalid extension: {ext}")
        return False

    return True

@app.route('/download')
def download():
    """
    Get the file name from the request and parse the name to get the file path.
    Send the file to the client as an attachment.
    """
    filename = request.args.get('filename')

    if not filename:
        logging.warning("Download request without filename.")
        abort(400, description="Filename not provided")

    # Validate filename (stringent allowlist - alphanumeric and limited special characters)
    if not is_safe_filename(filename):
        logging.warning(f"Invalid filename: {filename}")
        abort(400, description="Invalid filename")

    # Construct the full file path safely
    filepath = safe_join(app.config['UPLOAD_FOLDER'], filename)

    if filepath is None:
        logging.warning(f"Attempted access outside of UPLOAD_FOLDER: {filename}")
        abort(400, description="Invalid filename")

    # Check if the file exists
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        logging.warning(f"File not found: {filepath}")
        abort(404, description="File not found")

    try:
        # Determine MIME type (optional, but recommended)
        mime_type, _ = mimetypes.guess_type(filepath)
        if not mime_type:
            mime_type = 'application/octet-stream'  # Default binary type

        # Sanitize download_name (important!)
        download_name = os.path.basename(filename)  # Get just the filename part
        download_name = ''.join(c for c in download_name if c.isalnum() or c in ['.', '_', '-']) # Sanitize further

        # Set Content-Type Options to prevent sniffing
        headers = {'X-Content-Type-Options': 'nosniff'}

        # Send the file as an attachment
        logging.info(f"Sending file: {filepath}")
        response = send_file(filepath, as_attachment=True, download_name=download_name, mimetype=mime_type)
        response.headers['X-Content-Type-Options'] = 'nosniff'  # Set header on the response
        return response

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        abort(404, description="File not found")
    except PermissionError as e:
        logging.error(f"Permission error: {e}")
        abort(403, description="Permission denied")
    except OSError as e:
        logging.error(f"OS error: {e}")
        abort(500, description="Internal server error")
    except Exception as e:
        logging.error(f"Error sending file: {e}")
        abort(500, description="Internal server error")

    # Example of setting Content Security Policy (CSP) - adjust to your needs
    # @app.after_request
    # def add_csp_header(response):
    #     response.headers['Content-Security-Policy'] = "default-src 'self'"
    #     return response

if __name__ == '__main__':
    app.run(debug=False)

