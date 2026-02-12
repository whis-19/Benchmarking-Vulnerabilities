import os
from functools import wraps
from flask import Flask, request, send_file, abort, make_response
import html

app = Flask(__name__)

# Define the allowed image directory
ALLOWED_IMAGE_DIR = "images"

# Define the allowed image extensions
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif"}

# CSP Header - Adjust as needed for your application
CSP_POLICY = "default-src 'self'; img-src 'self' data:; script-src 'self';"

def secure_filename(filename):
    """
    Sanitizes a filename to prevent path traversal and other security issues.
    """
    if ".." in filename:
        return None  # Prevent path traversal

    # Check for multiple dots
    if filename.count(".") > 1:
        return None

    base, ext = os.path.splitext(filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return None  # Only allow specific file extensions

    return filename


def route(url):
    """
    Decorator to associate a URL with a function.
    """
    def decorator(f):
        @app.route(url)
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
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
        abort(400, "Missing 'name' parameter")

    # Sanitize the filename
    filename = secure_filename(name)

    if not filename:
        abort(400, "Invalid filename")

    # Construct the full file path
    filepath = os.path.join(ALLOWED_IMAGE_DIR, filename)

    # Check if the file exists within the allowed directory
    if not os.path.isfile(filepath):
        abort(404, "File not found")

    try:
        # Send the file as a response
        response = send_file(filepath, as_attachment=False)  # as_attachment=False displays in browser
        response.headers['Content-Security-Policy'] = CSP_POLICY
        return response
    except FileNotFoundError:
        abort(404, "File not found")
    except Exception as e:
        print(f"Error serving file: {e}")  # Log the error
        abort(500, "Internal Server Error")


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['Content-Security-Policy'] = CSP_POLICY
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.errorhandler(400)
def bad_request(error):
    """Handles 400 Bad Request errors."""
    message = html.escape(str(error))  # Escape the error message
    return make_response(f"<h1>Bad Request</h1><p>{message}</p>", 400)


@app.errorhandler(404)
def not_found(error):
    """Handles 404 Not Found errors."""
    message = html.escape(str(error))  # Escape the error message
    return make_response(f"<h1>Not Found</h1><p>{message}</p>", 404)


@app.errorhandler(500)
def internal_server_error(error):
    """Handles 500 Internal Server Error."""
    message = html.escape(str(error))  # Escape the error message
    return make_response(f"<h1>Internal Server Error</h1><p>{message}</p>", 500)


if __name__ == "__main__":
    # Create the allowed image directory if it doesn't exist
    if not os.path.exists(ALLOWED_IMAGE_DIR):
        os.makedirs(ALLOWED_IMAGE_DIR)

    # Example: Add a sample image (for testing)
    sample_image_path = os.path.join(ALLOWED_IMAGE_DIR, "test.png")
    if not os.path.exists(sample_image_path):
        # Create a blank image
        from PIL import Image
        img = Image.new('RGB', (100, 30), color='white')
        img.save(sample_image_path)

    app.run(debug=True, host="0.0.0.0", port=5000)

