from flask import request, send_file, Flask
import os
import logging
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for session management (if used)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define allowed file extensions and upload directory
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Example: Add your allowed extensions
UPLOAD_DIRECTORY = '/safe/path/to/files'  # Replace with a safe, absolute path

# Ensure the upload directory exists
if not os.path.exists(UPLOAD_DIRECTORY):
    try:
        os.makedirs(UPLOAD_DIRECTORY)
        logging.info(f"Created upload directory: {UPLOAD_DIRECTORY}")
    except OSError as e:
        logging.error(f"Failed to create upload directory: {e}")
        # Handle the error appropriately, e.g., exit the application

def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    response.headers['Cache-Control'] = 'no-store' # Prevent caching
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/download')
def download():
    """
    Get the file name from the request and parse the name to get the file path.
    Send the file to the client as an attachment.
    """
    filename = request.args.get('filename')

    if not filename:
        logging.warning("Download request without filename.")
        return "Filename missing", 400

    # Sanitize the filename using secure_filename
    filename = secure_filename(filename)

    if not filename:
        logging.warning("Invalid filename after sanitization.")
        return "Invalid filename", 400

    # Construct the full file path
    filepath = os.path.join(UPLOAD_DIRECTORY, filename)

    # Validate the file path to prevent path traversal
    if not os.path.abspath(filepath).startswith(UPLOAD_DIRECTORY):
        logging.warning(f"Attempted path traversal: {filepath}")
        return "Invalid file path", 400

    # Check if the file exists
    if not os.path.isfile(filepath):
        logging.warning(f"File not found: {filepath}")
        return "File not found", 404

    # Check if the file extension is allowed
    if not allowed_file(filename):
        logging.warning(f"File extension not allowed: {filename}")
        return "File type not allowed", 400

    try:
        # Send the file as an attachment
        logging.info(f"Sending file: {filepath}")
        return send_file(filepath, as_attachment=True, download_name=filename) # Specify download_name for user-friendly filename
    except Exception as e:
        logging.exception(f"Error sending file: {e}")
        return "Error sending file", 500

if __name__ == '__main__':
    # Use HTTPS in production
    # app.run(debug=True, ssl_context='adhoc') # For development only (self-signed certificate)
    app.run(debug=True) # Remove ssl_context for production and configure a proper web server (e.g., nginx, apache) to handle HTTPS

