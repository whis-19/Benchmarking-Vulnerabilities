from flask import Flask, request
import os
import re

app = Flask(__name__)

# Define a safe directory to store files
SAFE_DIRECTORY = "/app/safe_files"  # Or any other secure location
# Ensure the safe directory exists
os.makedirs(SAFE_DIRECTORY, exist_ok=True)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv'}  # Example allowed extensions
ALLOWED_FILENAME_CHARS = re.compile(r"^[a-zA-Z0-9._-]+$") # Allow only alphanumeric characters, underscores, periods, and hyphens

def is_safe_path(filename):
    """
    Checks if the provided filename is safe.

    Args:
        filename (str): The filename to check.

    Returns:
        bool: True if the filename is safe, False otherwise.
    """
    if ".." in filename:
        return False  # Prevent path traversal

    if filename.count(".") > 1:
        return False # Prevent multiple periods

    if not ALLOWED_FILENAME_CHARS.match(filename):
        return False # Check for invalid characters

    return True

def get_extension(filename):
    """
    Extracts the extension from a filename.

    Args:
        filename (str): The filename.

    Returns:
        str: The extension (without the dot), or an empty string if no extension is found.
    """
    try:
        return filename.rsplit('.', 1)[1].lower()
    except IndexError:
        return ''

@app.route('/open_file')
def open_file():
    """
    Get the file name from the request using 'file_name' and check if the file opens successfully in the given path from the current directory.

    :return: The file object if the file opens successfully, None otherwise.
    """
    filename = request.args.get('file_name')

    if not filename:
        return "File name not provided", 400

    if not is_safe_path(filename):
        return "Invalid file name", 400

    extension = get_extension(filename)
    if extension not in ALLOWED_EXTENSIONS:
        return "Invalid file extension", 400

    # Sanitize the filename using os.path.basename to prevent path injection
    filename = os.path.basename(filename)

    # Construct the full safe path
    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Canonicalize the path to resolve symbolic links and ".." components
    filepath = os.path.realpath(filepath)

    # Double-check that the file is still within the safe directory after canonicalization
    if not filepath.startswith(os.path.realpath(SAFE_DIRECTORY) + os.sep):
        return "Path traversal detected", 400

    try:
        f = open(filepath, 'r')  # Open in read mode
        # Process the file (e.g., read its contents)
        file_content = f.read()
        return file_content, 200 # Return the content

    except FileNotFoundError:
        return "File not found", 404
    except IOError as e:
        return f"Error opening file: {e}", 500
    finally:
        if 'f' in locals() and f:
            f.close() # Ensure the file is closed

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

