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
        url_path (str): The URL path to associate with the image serving function.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(filename):
            """
            Wrapped function that handles image serving.

            Args:
                filename (str): The name of the image file to serve.

            Returns:
                Response: The image file if found, otherwise an error response.
            """
            return f(filename)

        app.add_url_rule(url_path + '/<filename>', view_func=decorated_function)
        return decorated_function

    return decorator


def is_allowed_file(filename):
    """
    Checks if the file extension is allowed.

    Args:
        filename (str): The name of the file.

    Returns:
        bool: True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@image_route('/images')
def serve_image(filename):
    """
    Serves an image file from the images folder.

    Args:
        filename (str): The name of the image file to serve.

    Returns:
        Response: The image file if found and allowed, otherwise an error response.
    """
    if not is_allowed_file(filename):
        abort(400, "Invalid file extension")  # Bad Request

    filepath = os.path.join(IMAGES_FOLDER, filename)

    if os.path.isfile(filepath):
        try:
            return send_from_directory(IMAGES_FOLDER, filename)
        except Exception as e:
            print(f"Error serving file: {e}")  # Log the error
            abort(500, "Internal Server Error") # Internal Server Error
    else:
        abort(404, "Image not found")  # Not Found


if __name__ == '__main__':
    # Create the images folder if it doesn't exist
    if not os.path.exists(IMAGES_FOLDER):
        os.makedirs(IMAGES_FOLDER)

    # Example usage:  Place image files (e.g., 'example.jpg') in the 'images' folder.
    # Access the image via:  /images/example.jpg

    app.run(debug=True)  #  Disable debug mode in production!

