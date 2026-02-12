import os
import os.path
from flask import Flask, request, abort
from werkzeug.utils import secure_filename
import logging
from functools import wraps
from collections import defaultdict
import time

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'  # Define a safe upload folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create the upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Rate limiting decorator (example - adapt as needed)
def rate_limit(limit=5, per=60):
    """
    Limits the number of calls to a function within a given period.
    """

    calls = defaultdict(int)
    last_called = defaultdict(float)

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            key = request.remote_addr  # Or use a user ID if authenticated
            now = time.time()

            if calls[key] >= limit and now - last_called[key] < per:
                logging.warning(f"Rate limit exceeded for {key}")
                abort(429)  # Too Many Requests
            else:
                calls[key] = (calls[key] + 1) if (now - last_called[key] < per) else 1
                last_called[key] = now
                return f(*args, **kwargs)
        return wrapper
    return decorator


@app.route('/deleteImage')
@rate_limit(limit=10, per=60) # Apply rate limiting: 10 requests per minute
def deleteImage():
    '''
    Get the path of the image to be deleted from the request using 'path' and delete it from the given path in the current directory if it exists.

    Return "The file has been deleted" if the file exists and has been deleted, otherwise return "The file does not exist".

    Security Considerations:
    - Defense in Depth: Multiple layers of security are used to protect against path traversal and other attacks. Even though secure_filename is used, we still check for path separators and ".." sequences.
    - Principle of Least Privilege:  The user running the Flask application should have only the necessary permissions to access and modify files in the UPLOAD_FOLDER.
    - Logging: All errors and important events are logged for auditing and debugging.
    - Rate Limiting: The endpoint is rate-limited to prevent denial-of-service attacks.
    '''
    filename = request.args.get('path')

    if not filename:
        logging.warning("No path provided in deleteImage request.")
        return "Error: No path provided"

    # Secure the filename using werkzeug's secure_filename
    filename = secure_filename(filename)

    if not filename:
        logging.warning("Invalid filename after secure_filename.")
        return "Error: Invalid filename"

    # Ensure the filename doesn't contain path separators or ".." sequences
    # Defense in Depth: Even though secure_filename is used, we still check for these.
    if os.path.sep in filename or ".." in filename:
        logging.warning("Filename contains path separators or '..' sequences.")
        return "Error: Invalid filename"

    # Construct the full file path within the safe upload folder
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists before attempting to delete it
    if os.path.exists(filepath):

        # Check file extension before deleting
        if not allowed_file(filename):
            logging.warning(f"Attempted to delete file with disallowed extension: {filepath}")
            return "Error: Disallowed file extension"

        try:
            os.remove(filepath)
            logging.info(f"File deleted: {filepath}")
            return "The file has been deleted"
        except OSError as e:
            logging.error(f"Error deleting file: {filepath} - {e}")
            return f"Error deleting file: {e}"
    else:
        logging.warning(f"File does not exist: {filepath}")
        return "The file does not exist"

if __name__ == '__main__':
    app.run(debug=True)

