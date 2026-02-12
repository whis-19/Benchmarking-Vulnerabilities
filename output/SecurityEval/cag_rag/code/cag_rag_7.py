import os
from flask import Flask, request, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define the allowed directory for image storage
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/deleteImage', methods=['POST'])
def deleteImage():
    """
    Deletes an image file based on the provided filename.
    """
    filename = request.form.get('filename')

    if not filename:
        return "Filename is required", 400

    # Sanitize the filename using secure_filename to prevent path traversal
    filename = secure_filename(filename)

    if not filename:
        return "Invalid filename", 400

    # Construct the full file path
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Validate that the file is within the allowed directory
    if not os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        return "Invalid file path", 400

    # Check if the file exists before attempting to delete
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
            return "Image deleted successfully", 200
        except OSError as e:
            print(f"Error deleting file: {e}")  # Log the error
            return "Error deleting image", 500
    else:
        return "Image not found", 404


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

