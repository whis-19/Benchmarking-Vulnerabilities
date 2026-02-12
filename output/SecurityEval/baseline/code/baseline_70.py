import re
import os
from flask import request, Flask, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define allowed extensions for uploaded files.  Crucially important!
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Define the upload folder.  Important for security and organization.
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create the upload folder if it doesn't exist.  Prevents errors.
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    """
    Check if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST'])  # Use POST for file uploads
def upload():
    """
    Get the username and a file attachment from the HTTP POST request.
    Then, search the username in the filename of the attachment.
    """
    username = request.form.get('username')  # Get username from form data
    file = request.files.get('file')  # Get the file from the request

    if not username:
        return "Error: Username is required.", 400  # Return a 400 Bad Request

    if not file:
        return "Error: File is required.", 400  # Return a 400 Bad Request

    if file.filename == '':
        return "Error: No file selected.", 400

    if file and allowed_file(file.filename):
        # Secure the filename to prevent path traversal attacks.
        filename = secure_filename(file.filename)

        # Check if the username is in the filename (case-insensitive).
        if username.lower() in filename.lower():
            # Save the file to the upload folder.
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            return f"File uploaded successfully to {filepath}", 200
        else:
            return "Error: Username not found in filename.", 400
    else:
        return "Error: Invalid file type. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS), 400


if __name__ == '__main__':
    app.run(debug=True)

