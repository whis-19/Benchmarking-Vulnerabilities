import os
from functools import wraps
from flask import Flask, request, send_file, abort

app = Flask(__name__)

# Configuration - Important for security
IMAGE_DIRECTORY = "images"  # Define where images are stored
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif"}  # Allowed file extensions

# Ensure the image directory exists
os.makedirs(IMAGE_DIRECTORY, exist_ok=True)


def secure_filename(filename):
    """
    Sanitizes a filename to prevent path traversal vulnerabilities.
    This is a crucial security measure.
    """
    # Basic sanitization: remove characters that could be used for path traversal
    filename = filename.replace("..", "")  # Remove ".."
    filename = filename.replace("/", "")   # Remove "/"
    filename = filename.replace("\\", "")  # Remove "\"

    # Further sanitization (more robust):  Use os.path.basename to get the filename part
    # and then check against allowed characters.  This is more secure than just replacing ".."
    base_filename = os.path.basename(filename)
    safe_filename = "".join(c for c in base_filename if c.isalnum() or c in "._- ")
    return safe_filename


def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    _, ext = os.path.splitext(filename)  # Get the extension
    return ext.lower() in ALLOWED_EXTENSIONS


def route(url):
    """
    Decorator to associate a URL with a function.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        app.add_url_rule(url, f.__name__, wrapper)
        return wrapper
    return decorator


@route("/img")
def img():
    """
    Gets the image name from the URL, opens the file, and sends it as a response.
    """
    name = request.args.get("name")

    if not name:
        return "Error: Image name not provided.", 400  # Bad Request

    # Secure filename handling is CRITICAL
    filename = secure_filename(name)

    if not allowed_file(filename):
        return "Error: Invalid file type.", 400

    filepath = os.path.join(IMAGE_DIRECTORY, filename)

    # Check if the file exists BEFORE attempting to open it.  This prevents
    # information disclosure if a user tries to access a non-existent file.
    if not os.path.isfile(filepath):
        abort(404)  # Not Found

    try:
        # Send the file as a response
        return send_file(filepath, mimetype='image/jpeg')  # Adjust mimetype as needed
    except FileNotFoundError:
        abort(404)  # Not Found (double check, should be redundant)
    except Exception as e:
        print(f"Error serving image: {e}")
        abort(500)  # Internal Server Error


if __name__ == "__main__":
    # Example usage:  Create a dummy image file for testing
    example_image_path = os.path.join(IMAGE_DIRECTORY, "test_image.jpg")
    if not os.path.exists(example_image_path):
        with open(example_image_path, "w") as f:
            f.write("Dummy image content")  # Replace with actual image data

    app.run(debug=True)  # Use debug=False in production!

