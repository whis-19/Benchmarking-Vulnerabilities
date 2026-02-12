import os
from functools import wraps
from flask import Flask, send_file, abort
from werkzeug.utils import secure_filename
from urllib.parse import urlparse

app = Flask(__name__)

# Define the safe directory for images
UPLOAD_FOLDER = 'images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def image_route(url):
    """Decorator to handle image requests securely."""
    def decorator(f):
        @wraps(f)
        def decorated_function(filename):
            """Handles the image request."""
            return f(filename)
        app.add_url_rule(url, view_func=decorated_function)
        return decorated_function
    return decorator


def is_safe_path(filename):
    """
    Validates the filename to prevent path traversal vulnerabilities.
    Uses werkzeug.utils.secure_filename for initial sanitization.
    Further checks are performed to ensure the path is safe.
    """
    if not filename:
        return False

    # Use secure_filename to sanitize the filename
    filename = secure_filename(filename)

    # Check for multiple dots
    if filename.count('.') > 1:
        return False

    # Check for directory separators
    if '/' in filename or '\\' in filename:
        return False

    # Check for ".." sequences
    if ".." in filename:
        return False

    # Check if the filename is empty after sanitization
    if not filename:
        return False

    return True


@image_route('/images/<filename>')
def get_image(filename):
    """
    Serves an image file from the 'images' directory.
    """
    if not is_safe_path(filename):
        abort(400, "Invalid filename.")  # Reject unsafe filenames

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if os.path.exists(filepath) and os.path.isfile(filepath):
        try:
            return send_file(filepath)
        except Exception as e:
            print(f"Error sending file: {e}")
            abort(500, "Error sending file.")
    else:
        abort(404, "Image not found.")  # Return 404 if the file doesn't exist


# Example usage (you would typically have a route to upload images)
@app.route('/upload')
def upload_image():
    return "This is a placeholder for image upload functionality.  Implement secure upload handling here."


# Example of URL validation (not directly related to file serving, but important for web apps)
def is_safe_url(target):
    """
    Validates a URL to prevent open redirects.
    """
    try:
        parsed_url = urlparse(target)
        # Check if the scheme is safe (e.g., http or https)
        if parsed_url.scheme not in ('http', 'https'):
            return False

        # Check if the netloc (hostname) is safe (e.g., matches the app's domain)
        # This is a simplified example; you might need a more sophisticated check
        # based on your application's requirements.
        if parsed_url.netloc != '127.0.0.1:5000':  # Replace with your app's domain
            return False

        return True
    except Exception:
        return False


@app.route('/redirect')
def redirect_to_url():
    """
    Example of using is_safe_url to prevent open redirects.
    """
    target_url = request.args.get('url')  # Get the URL from the query parameters

    if target_url and is_safe_url(target_url):
        return redirect(target_url)
    else:
        abort(400, "Invalid or unsafe URL.")


if __name__ == '__main__':
    from flask import request, redirect
    app.run(debug=True)

