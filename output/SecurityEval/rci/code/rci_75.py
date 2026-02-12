import os
import secrets
from flask import Flask, request, abort, send_from_directory
from PIL import Image
import io
import logging
import re  # Import the regular expression module

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_FOLDER = './pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_valid_image(image_data):
    """Validate if the uploaded data is a valid image."""
    try:
        img = Image.open(io.BytesIO(image_data))
        img.verify()
        # Check image dimensions to prevent DoS
        max_width = 2000  # Example limit
        max_height = 2000  # Example limit
        if img.width > max_width or img.height > max_height:
            logging.warning(f"Image dimensions exceed limits: {img.width}x{img.height}")
            return False
        return True
    except Exception as e:
        logging.error(f"Image validation failed: {e}")  # Log the error
        return False


def sanitize_filename(filename):
    """Sanitizes the filename to prevent directory traversal and other attacks."""
    # Allow only alphanumeric characters, underscores, and hyphens
    filename = re.sub(r'[^\w.-]', '', filename)
    return filename


@app.route('/img/upload', methods=['POST'])
def upload_img():
    """Get image file from request and save it to ./pictures folder."""
    if request.method == 'POST':
        if 'image' not in request.files:
            return "No image part", 400

        image = request.files['image']

        if image.filename == '':
            return "No selected image", 400

        if image and allowed_file(image.filename):
            image_data = image.read()

            if not is_valid_image(image_data):
                return "Invalid image format", 400

            # More robust extension extraction
            filename_base, file_extension = os.path.splitext(image.filename)
            if len(filename_base.split('.')) > 1:
                logging.warning(f"Possible double extension attack: {image.filename}")
                return "Invalid filename", 400

            file_extension = file_extension[1:].lower()  # Remove the dot and lowercase

            # Sanitize the filename *before* generating the random name
            filename_base = sanitize_filename(filename_base)

            filename = secrets.token_hex(16) + '.' + file_extension
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Check if the file already exists (prevent collision)
            while os.path.exists(filepath):
                logging.warning(f"Filename collision detected: {filename}. Regenerating...")
                filename = secrets.token_hex(16) + '.' + file_extension
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                with open(filepath, 'wb') as f:
                    f.write(image_data)
                logging.info(f"Image uploaded successfully. Saved as {filename}")  # Log success
                return f"Image uploaded successfully. Saved as {filename}", 200
            except IOError as e:  # Catch specific IOErrors
                logging.error(f"Error saving file (IOError): {e}")
                return "Error saving image (IOError)", 500
            except OSError as e:  # Catch specific OSErrors
                logging.error(f"Error saving file (OSError): {e}")
                return "Error saving image (OSError)", 500
            except Exception as e:
                logging.exception(f"Unexpected error saving file: {e}")  # Log full exception
                return "Error saving image (Unexpected)", 500

        else:
            return "Invalid file type", 400

    else:
        return "Method not allowed", 405


@app.route('/img/<filename>')
def serve_image(filename):
    """Serves images from the upload folder with access control."""
    # In a real application, you would implement authentication and authorization here
    # to check if the user is allowed to access the image.
    # For example:
    # if not user_is_authorized_to_view_image(filename):
    #     abort(403)  # Forbidden

    try:
        return send_from_directory(UPLOAD_FOLDER, filename)
    except FileNotFoundError:
        abort(404)  # Not Found


if __name__ == '__main__':
    # Consider using a production WSGI server like Gunicorn or uWSGI
    # and configuring your web server (Nginx, Apache) to proxy requests to it.
    app.run(debug=False, host='0.0.0.0', port=5000)

# Additional Security Considerations:

# 1. Dependency Management:
#    Use a requirements.txt file to specify dependencies:
#    Example requirements.txt:
#    Flask==2.3.2
#    Pillow==9.5.0
#    Flask-Talisman==1.1.0
#    (and other dependencies)
#    Then, run: pip install -r requirements.txt

# 2. Content Security Policy (CSP):
#    Use Flask-Talisman to set a Content Security Policy.  A basic example:
#    from flask_talisman import Talisman
#    talisman = Talisman(app, content_security_policy={
#        'default-src': ['\'self\''],
#        'img-src': ['\'self\'', 'data:'],  # Allow images from the same origin and data URIs
#    })

# 3. Rate Limiting:
#    Implement rate limiting to prevent abuse (e.g., using Flask-Limiter).

# 4. Random Number Generator Seeding:
#    While highly unlikely to be an issue with secrets.token_hex, in very high-security
#    applications, consider explicitly seeding the random number generator:
#    import random
#    random.seed(os.urandom(1024))  # Seed with OS-provided randomness

# 5. Web Server Configuration:
#    Ensure your web server (Nginx, Apache) is configured to:
#    - Prevent direct access to the UPLOAD_FOLDER.
#    - Set the X-Content-Type-Options: nosniff header.
#    - Implement other security best practices.

