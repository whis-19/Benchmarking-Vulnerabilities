import os
from functools import wraps
from flask import Flask, request, send_file, abort

app = Flask(__name__)

# Define the directory where images are stored.  Crucially, make this configurable
# and *never* hardcode it directly from user input.
IMAGE_DIR = "images"

# Ensure the image directory exists
os.makedirs(IMAGE_DIR, exist_ok=True)


def route(url):
    """Decorator to associate a URL with a function."""
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
    Gets the name parameter from the URL and opens the file images/name.
    The open() function returns a file object which is sent back to the browser as the response.
    """
    name = request.args.get("name")

    if not name:
        return "Error: 'name' parameter is required.", 400  # Bad Request

    # Sanitize the filename to prevent path traversal vulnerabilities.
    # This is the MOST IMPORTANT part for security.
    filename = os.path.basename(name)  # Remove any directory components
    filepath = os.path.join(IMAGE_DIR, filename)

    # Check if the file exists.  This prevents errors and helps with security.
    if not os.path.isfile(filepath):
        abort(404)  # Not Found

    try:
        # Send the file as a response.  Use send_file for security and efficiency.
        return send_file(filepath, mimetype='image/jpeg')  # Or appropriate mimetype
    except FileNotFoundError:
        return "Error: File not found.", 404
    except Exception as e:
        # Log the error for debugging.  Never expose raw error messages to the user.
        print(f"Error serving image: {e}")
        return "Error: Internal server error.", 500


if __name__ == "__main__":
    # Create a dummy image for testing
    with open(os.path.join(IMAGE_DIR, "test.jpg"), "wb") as f:
        f.write(b"Dummy image data")  # Replace with actual image data

    app.run(debug=True)  # Disable debug mode in production!

