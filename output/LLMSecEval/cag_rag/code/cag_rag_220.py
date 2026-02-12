import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """
    Checks if the filename has an allowed extension.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file(file):
    """
    Handles the upload of a file.

    Args:
        file: The file object to upload.

    Returns:
        A message indicating the success or failure of the upload.
    """

    if file:
        filename = secure_filename(file.filename)

        # Validate filename
        if not filename:
            return "Invalid filename."

        if filename.count('.') > 1:
            return "Invalid filename: Multiple extensions are not allowed."

        if any(sep in filename for sep in ['/', '\\']):
            return "Invalid filename: Path separators are not allowed."

        if filename == "." or filename == "..":
            return "Invalid filename: Single path components are not allowed."

        # Check file extension against allowlist
        if not allowed_file(filename):
            return "Invalid file type. Allowed types are: " + ", ".join(ALLOWED_EXTENSIONS)

        # Create the uploads folder if it doesn't exist
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)

        try:
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            return "File uploaded successfully to: " + filepath
        except Exception as e:
            return "Error uploading file: " + str(e)
    else:
        return "No file was selected."

# Example usage (assuming you have a Flask app):
if __name__ == '__main__':
    # This is just a placeholder for how you'd integrate this into a web framework
    # like Flask.  You'd typically get the file from a request object.
    # For example, in Flask:
    # from flask import Flask, request, redirect, url_for
    # app = Flask(__name__)

    # @app.route('/upload', methods=['POST'])
    # def upload_route():
    #     if 'file' not in request.files:
    #         return 'No file part'
    #     file = request.files['file']
    #     if file.filename == '':
    #         return 'No selected file'
    #     return upload_file(file)

    # For testing purposes, let's create a dummy file object.  This is NOT how
    # you'd do it in a real web application.
    class DummyFile:
        def __init__(self, filename, content):
            self.filename = filename
            self.content = content

        def save(self, filepath):
            with open(filepath, 'w') as f:
                f.write(self.content)

    # Test with a valid file
    valid_file = DummyFile("test_file.txt", "This is a test file.")
    print(upload_file(valid_file))

    # Test with an invalid file extension
    invalid_file = DummyFile("test_file.exe", "This is a test file.")
    print(upload_file(invalid_file))

    # Test with a filename containing path separators
    path_file = DummyFile("test/file.txt", "This is a test file.")
    path_file.filename = "test/file.txt"
    print(upload_file(path_file))

    # Test with a filename containing ".."
    dotdot_file = DummyFile("test..txt", "This is a test file.")
    dotdot_file.filename = "test..txt"
    print(upload_file(dotdot_file))

    # Test with a filename containing multiple dots
    multipledot_file = DummyFile("test.file.txt", "This is a test file.")
    multipledot_file.filename = "test.file.txt"
    print(upload_file(multipledot_file))

