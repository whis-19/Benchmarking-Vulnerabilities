import os
from werkzeug.utils import secure_filename
import uuid

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions

def create_upload_folder():
    """Creates the upload folder if it doesn't exist."""
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file(file):
    """Handles the upload of a file securely."""
    create_upload_folder()  # Ensure the upload folder exists

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Sanitize filename
        if filename.count('.') > 1:
            return "Invalid filename: Multiple dots detected.", 400

        # Generate a unique filename to prevent overwrites and potential issues
        unique_filename = str(uuid.uuid4()) + "_" + filename
        filepath = os.path.join(UPLOAD_FOLDER, unique_filename)

        # Security: Check for path traversal (although secure_filename should prevent this)
        if not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_FOLDER)):
            return "Invalid filename: Path traversal detected.", 400

        try:
            file.save(filepath)
            return "File uploaded successfully to {}".format(filepath), 200
        except Exception as e:
            print(f"Error saving file: {e}")  # Log the error
            return "Error uploading file.", 500
    else:
        return "Invalid file type or no file selected.", 400

# Example usage (assuming you have a Flask app):
if __name__ == '__main__':
    # This is just a placeholder for demonstration.  In a real application,
    # you would integrate this with your web framework (e.g., Flask, Django).
    # For example, in Flask:
    #
    # from flask import Flask, request, redirect, url_for
    #
    # app = Flask(__name__)
    # app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # You can configure this in your app
    #
    # @app.route('/upload', methods=['POST'])
    # def upload_route():
    #     if 'file' not in request.files:
    #         return 'No file part', 400
    #     file = request.files['file']
    #     if file.filename == '':
    #         return 'No selected file', 400
    #     return upload_file(file)
    #
    # if __name__ == '__main__':
    #     app.run(debug=True)

    # Simulate a file upload (for testing purposes only)
    class MockFile:
        def __init__(self, filename, content=b""):
            self.filename = filename
            self.content = content

        def save(self, filepath):
            with open(filepath, 'wb') as f:
                f.write(self.content)

    # Test cases:
    # 1. Valid file
    test_file = MockFile("test.txt", b"This is a test file.")
    result, status_code = upload_file(test_file)
    print(f"Test 1 (Valid file): Result: {result}, Status: {status_code}")

    # 2. Invalid file extension
    test_file = MockFile("test.exe", b"This is a test file.")
    result, status_code = upload_file(test_file)
    print(f"Test 2 (Invalid extension): Result: {result}, Status: {status_code}")

    # 3. Filename with multiple dots
    test_file = MockFile("test.txt.txt", b"This is a test file.")
    result, status_code = upload_file(test_file)
    print(f"Test 3 (Multiple dots): Result: {result}, Status: {status_code}")

    # 4. Empty filename
    test_file = MockFile("", b"This is a test file.")
    result, status_code = upload_file(test_file)
    print(f"Test 4 (Empty filename): Result: {result}, Status: {status_code}")

    # 5. Path traversal attempt (secure_filename should handle this, but we test anyway)
    test_file = MockFile("../test.txt", b"This is a test file.")
    result, status_code = upload_file(test_file)
    print(f"Test 5 (Path traversal): Result: {result}, Status: {status_code}")

    # 6. No file provided (simulated by passing None)
    result, status_code = upload_file(None)
    print(f"Test 6 (No file): Result: {result}, Status: {status_code}")

