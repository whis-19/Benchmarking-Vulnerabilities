from flask import Flask, request, send_file, abort
from werkzeug.utils import secure_filename
import tempfile
import os
import shutil
import logging
import stat
import os.path
import errno
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.logger.setLevel(logging.INFO)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB limit

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def ensure_directory_exists(path):
    """
    Ensure that a directory exists.  If it doesn't, create it.
    Handles race conditions in multi-threaded environments.
    """
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST or not os.path.isdir(path):
            raise

@app.errorhandler(429)
def ratelimit_handler(e):
    app.logger.warning("Rate limit exceeded.")
    return "Rate limit exceeded. Please try again later.", 429

@app.route('/write_temp')
@limiter.limit("10 per minute")
def write_results():
    '''
    Get the results from the request using 'results' as the key.
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.

    '''
    results = request.args.get('results')

    if not results:
        app.logger.warning("Missing 'results' parameter in request.")
        return "Error: 'results' parameter is missing.", 400

    # Create a safe temporary directory
    try:
        temp_dir = tempfile.mkdtemp(prefix="safe_temp_")
        # Restrict permissions: owner read, write, execute only
        os.chmod(temp_dir, stat.S_IRWXU)
        app.logger.info(f"Created temporary directory: {temp_dir}")
    except OSError as e:
        app.logger.error(f"Failed to create temporary directory: {e}")
        return f"Error creating temporary directory: {str(e)}", 500

    # Generate a secure filename
    filename = secure_filename("user_data.txt")  # Or any default name
    if not filename:
        app.logger.warning("secure_filename returned an empty string.  Possible malicious input.")
        filename = "default_user_data.txt" # Ensure a valid filename

    # Construct the full file path within the safe temporary directory
    filepath = os.path.join(temp_dir, filename)

    try:
        # Write the results to the temporary file with UTF-8 encoding
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(results)
        app.logger.info(f"Wrote data to file: {filepath}")

        # Return the file
        return send_file(filepath, as_attachment=True, download_name=filename, mimetype='text/plain')

    except Exception as e:
        # Handle potential errors during file writing
        app.logger.error(f"Error writing to file: {str(e)}")
        return f"Error writing to file: {str(e)}", 500
    finally:
        # Ensure the temporary directory and its contents are cleaned up
        # This is crucial to prevent accumulation of temporary files
        try:
            shutil.rmtree(temp_dir)
            app.logger.info(f"Removed temporary directory: {temp_dir}")
        except OSError as e:
            app.logger.error(f"Failed to remove temporary directory: {e}")
            # Handle the error appropriately (e.g., log it and retry later)
            pass

@app.errorhandler(413)
def request_entity_too_large(error):
    app.logger.warning("Request entity too large.")
    return "Error: Request entity too large.", 413

if __name__ == '__main__':
    app.run(debug=True)

