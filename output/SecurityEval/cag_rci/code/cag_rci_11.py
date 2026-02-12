import os
import uuid
import logging
from flask import send_file, abort
from flask import current_app as app  # Access app config

UPLOAD_FOLDER = '/path/to/secure/upload/directory'  # Outside web server's document root
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure logging (replace with your actual logging setup)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route('/download/<file_id>')
@requires_auth
def download_file(file_id):
    """Downloads a file based on file_id."""

    try:
        uuid.UUID(file_id)  # Validate file_id is a valid UUID
    except ValueError:
        logger.warning(f"Invalid file_id format: {file_id}")
        abort(400)  # Bad Request

    # Retrieve filename from database based on file_id (UUID)
    filename = get_filename_from_database(file_id)  # Implement this function

    if not filename:
        logger.warning(f"File not found in database for file_id: {file_id}")
        abort(404)

    # Sanitize the filename to prevent path traversal
    filename = os.path.basename(filename)

    if not filename:  # Check if basename returned an empty string
        logger.error(f"os.path.basename returned empty string for filename from database for file_id: {file_id}")
        abort(500)  # Internal Server Error

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(filepath):
        logger.warning(f"File not found on disk: {filepath} for file_id: {file_id}")
        abort(404)

    # Use a safe download name (e.g., based on file_id)
    safe_download_name = f"download-{file_id}"  # Or look up a safe name

    logger.info(f"Serving file: {filepath} as {safe_download_name} for file_id: {file_id}")
    return send_file(filepath, as_attachment=True, download_name=safe_download_name)

