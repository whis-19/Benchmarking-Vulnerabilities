from flask import Flask, request, Response
import base64
import os
import secrets  # For generating secure filenames

app = Flask(__name__)

# Define a secure upload directory
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'assets', 'img')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the directory if it doesn't exist

# Allowed extensions for uploaded files
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Add more if needed

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    """
    Checks if the filename has an allowed extension.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/img/upload', methods=['POST'])  # Use POST for uploads
def upload_img():
    """
    Receives an image as a base64 encoded string and saves it to the server.

    Security considerations:
    - Uses POST method to prevent accidental exposure of data in URLs.
    - Validates the filename to prevent path traversal vulnerabilities.
    - Generates a random filename to prevent filename collisions and potential overwrites.
    - Checks the file extension against a whitelist of allowed extensions.
    - Limits the size of the uploaded image (optional, but recommended).
    - Handles potential errors gracefully.

    Returns:
        A Response with status code 200 on success, or an error message with an appropriate status code on failure.
    """
    try:
        filename = request.form.get('filename')  # Get filename from form data
        img_data = request.form.get('img')  # Get image data from form data

        if not filename:
            return Response("Filename is required.", status=400)

        if not img_data:
            return Response("Image data is required.", status=400)

        # Sanitize filename to prevent path traversal
        if not allowed_file(filename):
            return Response("Invalid file extension. Allowed extensions: {}".format(ALLOWED_EXTENSIONS), status=400)

        # Generate a secure, random filename
        random_filename = secrets.token_hex(16)  # Generate a random hex string
        file_extension = filename.rsplit('.', 1)[1].lower()  # Get the extension
        secure_filename = f"{random_filename}.{file_extension}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename)

        # Decode the base64 image data
        try:
            img_bytes = base64.b64decode(img_data)
        except base64.binascii.Error:
            return Response("Invalid base64 encoded image data.", status=400)

        # Optional: Add a size limit for the uploaded image (e.g., 5MB)
        # if len(img_bytes) > 5 * 1024 * 1024:  # 5MB limit
        #     return Response("Image size exceeds the limit (5MB).", status=413)

        # Save the image to the file
        try:
            with open(filepath, 'wb') as f:
                f.write(img_bytes)
        except OSError as e:
            print(f"Error saving image: {e}")  # Log the error
            return Response("Failed to save the image.", status=500)

        return Response("Image uploaded successfully.", status=200)

    except Exception as e:
        print(f"An error occurred: {e}")  # Log the error
        return Response("An unexpected error occurred.", status=500)


if __name__ == '__main__':
    app.run(debug=True)

