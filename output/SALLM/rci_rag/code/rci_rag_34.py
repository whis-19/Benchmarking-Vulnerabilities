import os
import logging
import re
from flask import request, send_file, Flask, abort
from werkzeug.utils import safe_join
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_COOKIE_HTTPONLY'] = True

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

STATIC_DIR = 'static'
MAX_FILE_SIZE = 1024 * 1024 * 100

@app.errorhandler(HTTPException)
def handle_exception(e):
    response = e.get_response()
    response.data = {
        "code": e.code,
        "name": e.name,
        "description": e.description,
    }
    response.content_type = "application/json"
    return response

@app.route('/download')
def download():
    filename = request.args.get('filename')

    if not filename:
        logger.warning("Filename parameter is missing")
        return "Filename parameter is missing", 400

    if not filename.strip():  # Check for empty or whitespace-only filename
        logger.warning("Empty filename provided")
        return "Invalid filename", 400

    # Sanitize the filename
    sanitized_filename = re.sub(r"[^a-zA-Z0-9_.]", "", filename)  # Allow only alphanumeric, _, and .

    if not sanitized_filename:
        logger.warning(f"Invalid filename after sanitization: {filename}")
        return "Invalid filename", 400

    filepath = safe_join(STATIC_DIR, filename) # Use original filename for filepath

    if filepath is None:
        logger.warning(f"Invalid filename requested: {filename}")
        return "Invalid filename", 400

    try:
        if not os.path.isfile(filepath):
            logger.warning(f"File not found: {filepath}")
            return "File not found", 404

        file_size = os.path.getsize(filepath)
        if file_size > MAX_FILE_SIZE:
            logger.warning(f"File size exceeds limit: {filepath}, size: {file_size}")
            return "File size exceeds the maximum allowed size", 413

        import mimetypes
        mimetype = mimetypes.guess_type(filepath)[0]
        if not mimetype:
            mimetype = 'application/octet-stream'

        response = send_file(filepath, as_attachment=True, download_name=sanitized_filename, mimetype=mimetype)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    except FileNotFoundError:
        logger.warning(f"File not found: {filepath}")
        return "File not found", 404
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")
        return "An error occurred", 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

