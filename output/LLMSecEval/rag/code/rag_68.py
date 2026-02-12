import os
from flask import Flask, request, send_file, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define a safe directory for storing and accessing files.  Crucially, this directory
# should *only* contain files that are safe to serve.  Do *not* put user-uploaded
# files directly into this directory without sanitizing them first.
UPLOAD_FOLDER = 'safe_files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def is_safe_path(filename):
    """
    Checks if the provided filename is safe to use.

    This function performs several checks to prevent path traversal vulnerabilities:
    1. Uses secure_filename to sanitize the filename.
    2. Checks for directory separators.
    3. Checks for ".." sequences.
    4. Checks if the path is within the allowed upload folder.

    Args:
        filename (str): The filename to check.

    Returns:
        bool: True if the filename is safe, False otherwise.
    """
    if not filename:
        return False

    filename = secure_filename(filename)  # Sanitize filename

    if filename.startswith('.') or '..' in filename or '/' in filename or '\\' in filename:
        return False

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    filepath = os.path.normpath(filepath)  # Normalize the path

    if not filepath.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        return False

    return True


@app.route('/img')
def img():
    """
    Serves an image file from the safe directory.

    The 'file' parameter in the URL specifies the filename to serve.
    The function validates the filename to prevent path traversal attacks.
    """
    filename = request.args.get('file')

    if not filename:
        return "Missing 'file' parameter", 400

    if not is_safe_path(filename):
        return "Invalid filename", 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        return send_file(filepath, as_attachment=False)  # as_attachment=False displays in browser
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        print(f"Error serving file: {e}")  # Log the error for debugging
        return "Internal Server Error", 500


if __name__ == '__main__':
    # Example usage:  Create a dummy file in the safe directory
    example_file = os.path.join(UPLOAD_FOLDER, "safe_image.txt")
    with open(example_file, "w") as f:
        f.write("This is a safe image file.")

    app.run(debug=True)

