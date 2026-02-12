import os
from werkzeug.utils import secure_filename
import uuid

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def create_upload_folder():
    """Creates the upload folder if it doesn't exist."""
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file(file):
    """Handles the upload of a file securely.

    Args:
        file: The file object to upload.

    Returns:
        The filename of the saved file, or None if the upload failed.
    """
    create_upload_folder()

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Sanitize filename
        if filename.count('.') > 1:
            return None # Reject filenames with multiple extensions

        # Generate a unique filename to prevent overwrites and potential issues
        unique_id = uuid.uuid4()
        base, ext = os.path.splitext(filename)
        filename = f"{base}_{unique_id}{ext}"

        filepath = os.path.join(UPLOAD_FOLDER, filename)

        # Extra security checks (Redundant but good to have)
        if not filepath.startswith(os.path.abspath(UPLOAD_FOLDER)):
            return None  # Prevent path traversal

        try:
            file.save(filepath)
            return filename  # Return the filename for later use
        except Exception as e:
            print(f"Error saving file: {e}")
            return None
    else:
        return None  # Invalid file or extension

# Example usage (assuming you have a Flask app or similar)
if __name__ == '__main__':
    # This is just a simulation.  In a real application, 'file' would come from
    # a web request (e.g., Flask's request.files['file']).

    # Create a dummy file for testing
    with open("test.txt", "w") as f:
        f.write("This is a test file.")

    class MockFile:  # Simulate a file object from a web framework
        def __init__(self, filename):
            self.filename = filename

        def save(self, filepath):
            # In a real application, this would save the uploaded file.
            print(f"Simulating saving file to: {filepath}")

    # Simulate a successful upload
    mock_file = MockFile("my_document.txt")
    uploaded_filename = upload_file(mock_file)
    if uploaded_filename:
        print(f"File uploaded successfully as: {uploaded_filename}")
    else:
        print("File upload failed.")

    # Simulate a failed upload (invalid extension)
    mock_file_bad_ext = MockFile("my_document.exe")
    uploaded_filename = upload_file(mock_file_bad_ext)
    if uploaded_filename:
        print(f"File uploaded successfully as: {uploaded_filename}")
    else:
        print("File upload failed (invalid extension).")

    # Simulate a failed upload (multiple dots in filename)
    mock_file_multiple_dots = MockFile("my_document.txt.bak")
    uploaded_filename = upload_file(mock_file_multiple_dots)
    if uploaded_filename:
        print(f"File uploaded successfully as: {uploaded_filename}")
    else:
        print("File upload failed (multiple dots in filename).")

    # Clean up the dummy file
    os.remove("test.txt")

