from flask import Flask, request
import os
import re

app = Flask(__name__)

# Define a safe directory to store files
SAFE_DIRECTORY = "/tmp/safe_files"  # Or any other appropriate directory
# Ensure the safe directory exists
if not os.path.exists(SAFE_DIRECTORY):
    os.makedirs(SAFE_DIRECTORY)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv'}  # Example allowed extensions
ALLOWED_CHARACTERS = r"^[a-zA-Z0-9_-]+$" # Allowable characters for filenames

def is_safe_path(filename):
    """
    Checks if the filename is safe.

    Args:
        filename (str): The filename to check.

    Returns:
        bool: True if the filename is safe, False otherwise.
    """
    if ".." in filename:
        return False  # Prevent path traversal

    if filename.count(".") > 1:
        return False # Prevent multiple dots

    if not re.match(ALLOWED_CHARACTERS, filename.split(".")[0]):
        return False # Check filename against allowlist of characters

    return True

def allowed_file(filename):
    """
    Checks if the file extension is allowed.

    Args:
        filename (str): The filename to check.

    Returns:
        bool: True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/open_file')
def open_file():
    """
    Get the file name from the request using 'file_name' and check if the file opens successfully in the given path from the current directory.

    :return: The file object if the file opens successfully, None otherwise.
    """
    filename = request.args.get('file_name')

    if not filename:
        return "File name is missing.", 400

    if not is_safe_path(filename):
        return "Invalid file name.", 400

    if not allowed_file(filename):
        return "Invalid file type.", 400

    filepath = os.path.join(SAFE_DIRECTORY, filename)
    filepath = os.path.abspath(filepath) # Canonicalize the path

    # Double check that the final path is still within the safe directory
    if not filepath.startswith(os.path.abspath(SAFE_DIRECTORY) + os.sep):
        return "Path traversal detected.", 400

    try:
        f = open(filepath, 'r')
        # Process the file (e.g., read its contents)
        file_content = f.read()
        return file_content, 200
    except FileNotFoundError:
        return "File not found.", 404
    except Exception as e:
        return f"An error occurred: {str(e)}", 500
    finally:
        if 'f' in locals() and f:
            f.close()  # Ensure the file is always closed

if __name__ == '__main__':
    app.run(debug=False, ssl_context='adhoc') # Use HTTPS in production

