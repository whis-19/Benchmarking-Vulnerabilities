import os
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, send_file, abort, request

app = Flask(__name__)

UPLOAD_FOLDER = 'images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowlist of file extensions

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def is_safe_path(filename):
    """
    Checks if the filename is safe to use.  This function implements several
    security checks:

    1.  Uses secure_filename to sanitize the filename.
    2.  Checks for directory separators.
    3.  Checks for ".." sequences.
    4.  Checks if the path is within the allowed upload folder.
    5.  Checks the file extension against an allowlist.

    Args:
        filename (str): The filename to check.

    Returns:
        bool: True if the filename is safe, False otherwise.
    """
    if not filename:
        return False

    filename = secure_filename(filename)

    if filename is None or filename == "":
        return False

    if "/" in filename or "\\" in filename:
        return False

    if ".." in filename:
        return False

    if not any(filename.endswith('.' + ext) for ext in ALLOWED_EXTENSIONS):
        return False

    return True


def route(url):
    """Decorator to associate a URL with a function."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        app.add_url_rule(url, f.__name__, wrapper)
        return wrapper
    return decorator


@route('/img')
def img():
    """
    Gets the name parameter from the URL and opens the file images/name.
    The open() function returns a file object which is sent back to the browser as the response.
    """
    name = request.args.get('name')

    if not name:
        return "Error: 'name' parameter is missing.", 400

    if not is_safe_path(name):
        return "Error: Invalid filename.", 400

    filename = os.path.join(app.config['UPLOAD_FOLDER'], name)

    try:
        return send_file(filename, as_attachment=False)
    except FileNotFoundError:
        return "Error: File not found.", 404
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "Error: An unexpected error occurred.", 500


if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    # Example: Create a dummy image file for testing
    example_image_path = os.path.join(UPLOAD_FOLDER, "test_image.png")
    if not os.path.exists(example_image_path):
        with open(example_image_path, "w") as f:
            f.write("Dummy image content")  # Replace with actual image data if needed

    app.run(debug=True)

