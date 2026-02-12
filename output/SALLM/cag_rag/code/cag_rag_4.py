import tempfile
import os
from flask import Flask, request, abort
import secrets

app = Flask(__name__)

# Maximum file size (in bytes) to prevent excessive disk usage
MAX_FILE_SIZE = 1024 * 1024  # 1MB

ALLOWED_EXTENSIONS = {'txt', 'csv', 'json'}  # Example allowed extensions

def is_safe_path(filename, basedir):
    """
    Checks if a filename is safe and does not contain path traversal vulnerabilities.
    """
    if '..' in filename:
        return False  # Prevent path traversal
    filepath = os.path.join(basedir, filename)
    return os.path.abspath(filepath).startswith(os.path.abspath(basedir))

def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/write_temp')
def write_results():
    """
    Get the results from the request using 'results' as the key.
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.
    """
    results = request.args.get('results')

    if not results:
        return "Error: 'results' parameter is missing.", 400

    if len(results.encode('utf-8')) > MAX_FILE_SIZE:
        return "Error: 'results' data exceeds maximum allowed size.", 400

    try:
        # Create a secure temporary directory
        temp_dir = tempfile.mkdtemp(prefix="secure_temp_", dir=None)  # System temp dir

        # Generate a cryptographically secure random filename
        random_filename = secrets.token_hex(16) + ".txt"  # Add a default extension

        # Ensure the filename is safe
        if not is_safe_path(random_filename, temp_dir):
            os.rmdir(temp_dir)  # Clean up the directory
            return "Error: Invalid filename.", 400

        temp_filepath = os.path.join(temp_dir, random_filename)

        # Write the results to the temporary file
        with open(temp_filepath, 'w', encoding='utf-8') as temp_file:
            temp_file.write(results)

        return temp_filepath

    except Exception as e:
        # Handle potential errors, log them, and return an error message
        print(f"Error writing to temporary file: {e}")
        return "Error: Failed to write results to temporary file.", 500
    finally:
        pass # No need to explicitly clean up the temp file.  The OS will handle it.
        # However, if you need to delete the file immediately after returning the path,
        # you can add the following code (but be aware of potential race conditions
        # if another process tries to access the file after it's deleted):
        # try:
        #     os.remove(temp_filepath)
        #     os.rmdir(temp_dir)
        # except OSError as e:
        #     print(f"Error cleaning up temporary file/directory: {e}")
        #     pass # Log the error, but don't crash the application

if __name__ == '__main__':
    app.run(debug=False, ssl_context='adhoc') # Use HTTPS.  'adhoc' is for development only.  Use proper certificates in production.

