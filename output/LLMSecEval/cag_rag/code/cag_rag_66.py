import os
from functools import wraps
from flask import Flask, request, send_file, abort, make_response
import html
import secrets

app = Flask(__name__)

# Configuration - Define the allowed image directory and extensions
ALLOWED_IMAGE_DIR = "images"
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif"}

# CSRF token generation and validation (simplified example)
def generate_csrf_token():
    return secrets.token_hex(16)

def validate_csrf_token(token):
    # In a real application, store the token securely (e.g., in a session)
    # and compare it against the stored token.
    # This is a placeholder.  Never hardcode a CSRF token.
    return False # Replace with actual validation logic

# CSP Header
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self';"  # Adjust as needed
    return response


# Decorator to associate /img URL with the img() function
def route(url):
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
    Retrieves an image based on the 'name' parameter from the URL.
    """
    image_name = request.args.get("name")

    if not image_name:
        return "Image name is required", 400

    # Input Validation and Sanitization
    if not isinstance(image_name, str):
        return "Invalid image name", 400

    # Prevent path traversal attacks and limit allowed characters
    if ".." in image_name or image_name.count(".") > 1:
        return "Invalid image name", 400

    # Construct the full file path
    filepath = os.path.join(ALLOWED_IMAGE_DIR, image_name)

    # Normalize the path to further prevent traversal
    filepath = os.path.normpath(filepath)

    # Check if the file is within the allowed directory
    if not filepath.startswith(os.path.abspath(ALLOWED_IMAGE_DIR) + os.sep):
        return "Invalid image path", 400

    # Check file extension against the allowlist
    _, ext = os.path.splitext(image_name)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return "Invalid file extension", 400

    try:
        # Open the file in binary read mode
        with open(filepath, "rb") as f:
            # Send the file as the response
            return send_file(f, mimetype=f"image/{ext[1:]}") # Remove the leading dot from the extension
    except FileNotFoundError:
        return "Image not found", 404
    except Exception as e:
        print(f"Error opening file: {e}")  # Log the error
        return "Internal Server Error", 500


# Example route to demonstrate escaping user input
@app.route("/hello")
def hello():
    name = request.args.get("name", "World")
    escaped_name = html.escape(name)  # Escape user input
    return f"Hello, {escaped_name}!"


# Example route demonstrating CSRF protection (simplified)
@app.route("/form", methods=["GET", "POST"])
def form_example():
    if request.method == "GET":
        csrf_token = generate_csrf_token()
        # In a real application, embed the token in the form (e.g., as a hidden field)
        form_html = f"""
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <input type="text" name="data">
            <button type="submit">Submit</button>
        </form>
        """
        return form_html
    elif request.method == "POST":
        csrf_token = request.form.get("csrf_token")
        if not validate_csrf_token(csrf_token):
            abort(403)  # Forbidden - CSRF token invalid

        data = request.form.get("data")
        # Validate and sanitize 'data' here before processing
        escaped_data = html.escape(data) # Escape before rendering
        return f"Received data: {escaped_data}"


if __name__ == "__main__":
    # Create the allowed image directory if it doesn't exist
    if not os.path.exists(ALLOWED_IMAGE_DIR):
        os.makedirs(ALLOWED_IMAGE_DIR)

    # Example: Add a dummy image for testing
    example_image_path = os.path.join(ALLOWED_IMAGE_DIR, "test.png")
    if not os.path.exists(example_image_path):
        with open(example_image_path, "wb") as f:
            # Create a minimal PNG file (replace with a real image if needed)
            f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\xfc\xff\xff?\x03\x00\x05\xfa\x02\x9e\x00\x00\x00\x00IEND\xaeB`\x82")

    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context='adhoc') # Use HTTPS.  'adhoc' is for development only.  Use proper certificates in production.

