import os
from functools import wraps
from flask import Flask, send_from_directory, abort
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the safe directory for images
UPLOAD_FOLDER = 'images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def image_route(url):
    """
    Decorator to handle image requests securely.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(filename):
            """
            Handles the image request.
            """
            try:
                # Validate filename using secure_filename
                validated_filename = secure_filename(filename)

                # Check for multiple dots
                if validated_filename.count('.') > 1:
                    logging.warning(f"Multiple dots detected in filename: {filename}")
                    abort(400)  # Bad Request

                # Check for directory separators
                if '/' in validated_filename or '\\' in validated_filename:
                    logging.warning(f"Directory separators detected in filename: {filename}")
                    abort(400)  # Bad Request

                # Check for ".." sequences
                if ".." in validated_filename:
                    logging.warning(f'".." sequence detected in filename: {filename}')
                    abort(400)  # Bad Request

                # Construct the full file path
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], validated_filename)

                # Normalize the path and check if it's relative and doesn't contain ".."
                normalized_path = os.path.normpath(filepath)
                if not normalized_path.startswith(app.config['UPLOAD_FOLDER']) or ".." in normalized_path:
                    logging.warning(f"Invalid path: {filepath} (normalized: {normalized_path})")
                    abort(400)  # Bad Request

                # Check if the file exists
                if not os.path.isfile(filepath):
                    logging.warning(f"File not found: {filepath}")
                    abort(404)  # Not Found

                # Send the file to the browser
                logging.info(f"Serving file: {filepath}")
                return send_from_directory(app.config['UPLOAD_FOLDER'], validated_filename)

            except Exception as e:
                logging.error(f"Error processing file: {filename} - {e}")
                abort(500)  # Internal Server Error

        app.add_url_rule(url + '<filename>', view_func=decorated_function)
        return decorated_function

    return decorator


@image_route('/images/')
def get_image(filename):
    """
    Serves the requested image file.
    """
    pass  # The actual logic is handled by the decorator


if __name__ == '__main__':
    # Example usage:  Place an image file (e.g., "myimage.jpg") in the "images" folder.
    # Then, access it via:  http://127.0.0.1:5000/images/myimage.jpg

    app.run(debug=True)

