from flask import Flask, request, redirect, abort
import base64
import os
import secrets  # For generating secure filenames
from PIL import Image  # For image validation
import io

app = Flask(__name__)

# Configuration - Important for security
UPLOAD_FOLDER = './pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Restrict allowed file types
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit - prevent DoS

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """
    Check if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_valid_image(image_data):
    """
    Validate if the uploaded data is a valid image.  This helps prevent
    malicious file uploads disguised as images.
    """
    try:
        img = Image.open(io.BytesIO(image_data))
        img.verify()  # Verify that it is indeed an image
        return True
    except:
        return False


@app.route('/img/upload', methods=['POST'])  # Use POST for uploads
def upload_img():
    """
    Get image file from request and save it to ./pictures folder after encoding.
    """
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'image' not in request.files:  # Changed 'file' to 'image' for clarity
            return "No image part", 400  # Bad Request

        image = request.files['image']  # Changed 'file' to 'image'

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if image.filename == '':
            return "No selected image", 400  # Bad Request

        if image and allowed_file(image.filename):
            # Read the image data
            image_data = image.read()

            # Validate the image data
            if not is_valid_image(image_data):
                return "Invalid image format", 400

            # Generate a secure filename
            filename = secrets.token_hex(16) + '.' + image.filename.rsplit('.', 1)[1].lower()
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Save the image file
            try:
                with open(filepath, 'wb') as f:
                    f.write(image_data)
            except Exception as e:
                print(f"Error saving file: {e}")
                return "Error saving image", 500  # Internal Server Error

            # Return a success message (or redirect to a success page)
            return f"Image uploaded successfully. Saved as {filename}", 200

        else:
            return "Invalid file type", 400  # Bad Request

    else:
        return "Method not allowed", 405  # Method Not Allowed


if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!
    # It can expose sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

