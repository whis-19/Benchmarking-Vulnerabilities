import os
from flask import Flask, request, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define the directory where images are stored.  Crucially, this should be
# outside the web server's document root to prevent direct access.
UPLOAD_FOLDER = '/path/to/your/image/storage'  # Replace with a secure path
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed file extensions (restrict to image types)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    """
    Checks if the filename has an allowed extension.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/deleteImage', methods=['POST'])  # Use POST for deletion
def deleteImage():
    """
    Deletes an image file based on the filename provided in the request.

    Security Considerations:
    - Uses secure_filename to prevent path traversal vulnerabilities.
    - Restricts allowed file extensions to prevent execution of arbitrary files.
    - Checks if the file exists before attempting to delete it.
    - Uses POST method to prevent accidental deletion via GET requests.
    - Requires authentication/authorization (see below).
    """

    # Authentication/Authorization:  **CRITICAL**
    #  This is a placeholder.  You MUST implement proper authentication and
    #  authorization to ensure only authorized users can delete files.
    #  Examples:  API keys, JWT tokens, session-based authentication.
    #  Without this, anyone can delete any file!
    if not is_user_authorized(request):  # Replace with your auth check
        abort(403)  # Forbidden

    filename = request.form.get('filename')  # Get filename from POST data

    if not filename:
        return "Filename is required", 400  # Bad Request

    if not allowed_file(filename):
        return "Invalid file type", 400

    # Secure the filename to prevent path traversal attacks
    filename = secure_filename(filename)

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists before attempting to delete it
    if not os.path.exists(filepath):
        return "File not found", 404  # Not Found

    try:
        os.remove(filepath)
        return "File deleted successfully", 200  # OK
    except OSError as e:
        print(f"Error deleting file: {e}")  # Log the error
        return "Error deleting file", 500  # Internal Server Error


def is_user_authorized(request):
    """
    Placeholder for authentication/authorization logic.  **MUST BE IMPLEMENTED.**

    This function should check if the user making the request is authorized
    to delete files.  This could involve checking API keys, JWT tokens,
    session cookies, or other authentication mechanisms.

    Returns:
        True if the user is authorized, False otherwise.
    """
    # **IMPLEMENT YOUR AUTHENTICATION/AUTHORIZATION HERE**
    # Example using a simple API key (NOT RECOMMENDED FOR PRODUCTION):
    api_key = request.headers.get('X-API-Key')
    if api_key == 'YOUR_SECRET_API_KEY':  # Replace with a real key
        return True
    else:
        return False


if __name__ == '__main__':
    # Ensure the upload folder exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    app.run(debug=True)  # Disable debug mode in production!

