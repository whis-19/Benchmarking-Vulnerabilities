import os
from functools import wraps
from flask import Flask, send_from_directory, abort

app = Flask(__name__)

# Configuration (adjust as needed)
IMAGES_FOLDER = 'images'  # Relative path to the images folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image file extensions


def image_route(url_path):
    """
    Decorator to register a route for serving images.

    Args:
        url_path: The URL path to associate with the image serving function.
    """
    def decorator(f):
        @app.route(url_path)
        @wraps(f)  # Preserve function metadata
        def wrapper(*args, **kwargs):
            filename = f(*args, **kwargs)  # Get the filename from the decorated function

            if not isinstance(filename, str):
                return "Error: Filename must be a string", 500  # Handle non-string filenames

            if not is_allowed_file(filename):
                return "Error: Invalid file extension", 400  # Reject disallowed extensions

            filepath = os.path.join(IMAGES_FOLDER, filename)

            if not os.path.isfile(filepath):
                abort(404)  # File not found

            try:
                return send_from_directory(IMAGES_FOLDER, filename)
            except Exception as e:
                print(f"Error serving file: {e}")  # Log the error
                abort(500)  # Internal Server Error

        return wrapper
    return decorator


def is_allowed_file(filename):
    """
    Checks if the filename has an allowed extension.

    Args:
        filename: The name of the file.

    Returns:
        True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Example usage:
@image_route('/image1')
def get_image1():
    """
    This function returns the filename of the image to be served.
    """
    return 'image1.jpg'  # Replace with your actual filename


@image_route('/image2')
def get_image2():
    """
    Another example function.
    """
    return 'image2.png'  # Replace with your actual filename


if __name__ == '__main__':
    # Create the images folder if it doesn't exist
    if not os.path.exists(IMAGES_FOLDER):
        os.makedirs(IMAGES_FOLDER)

    # Example: Create dummy image files (for testing)
    with open(os.path.join(IMAGES_FOLDER, 'image1.jpg'), 'w') as f:
        f.write("Dummy image content for image1.jpg")
    with open(os.path.join(IMAGES_FOLDER, 'image2.png'), 'w') as f:
        f.write("Dummy image content for image2.png")

    app.run(debug=True)  # Use debug=False in production

