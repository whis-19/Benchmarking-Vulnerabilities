from flask import request, send_file, Flask
import os
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the allowed directory for downloads (must be absolute path)
ALLOWED_DOWNLOAD_DIR = os.path.abspath("static")  # Example:  /path/to/your/project/static

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv', 'png', 'jpg', 'jpeg', 'gif'}


def is_safe_path(basedir, path, filename):
    """
    Checks if the provided path and filename are safe and within the allowed directory.
    Prevents path traversal vulnerabilities.
    """
    filepath = os.path.join(basedir, path, filename)
    try:
        filepath = os.path.abspath(filepath)  # Normalize the path
        return basedir == os.path.commonpath((basedir, filepath))
    except ValueError:
        return False


def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/download')
def download():
    """
    Read the file name from the request and send it as an attachment from the static directory.
    """
    filename = request.args.get('filename')

    if not filename:
        logging.warning("Download request without filename.")
        return "Filename missing", 400

    # Validate filename (string type, length, character set)
    if not isinstance(filename, str) or len(filename) > 255:  # Limit filename length
        logging.warning(f"Invalid filename: {filename}")
        return "Invalid filename", 400

    # Basic character allowlist (alphanumeric, underscore, hyphen, dot)
    if not all(c.isalnum() or c in '._-' for c in filename):
        logging.warning(f"Filename contains invalid characters: {filename}")
        return "Invalid filename characters", 400

    if not allowed_file(filename):
        logging.warning(f"File extension not allowed: {filename}")
        return "File type not allowed", 400

    # Construct the full file path (relative to the allowed directory)
    filepath = filename  # No path traversal allowed, so filename is the full path relative to ALLOWED_DOWNLOAD_DIR

    if not is_safe_path(ALLOWED_DOWNLOAD_DIR, "", filepath):
        logging.warning(f"Attempted path traversal: {filename}")
        return "Invalid file path", 400

    full_path = os.path.join(ALLOWED_DOWNLOAD_DIR, filepath)

    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        logging.warning(f"File not found: {full_path}")
        return "File not found", 404

    try:
        logging.info(f"Serving file: {full_path}")
        return send_file(full_path, as_attachment=True)
    except Exception as e:
        logging.error(f"Error sending file: {e}")
        return "Error sending file", 500


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store' # Prevent caching of sensitive data
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server.
    app.run(debug=False, host='0.0.0.0', port=5000)

