import os
from flask import Flask, request, send_file, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'  # Define a safe upload folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions
MAX_FILE_SIZE = 1024 * 1024 * 10 # 10MB limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    """
    Checks if the filename has an allowed extension.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_path(path):
    """
    Checks if the path is safe.  This function implements several security checks.
    """
    if not path:
        return False

    if ".." in path:
        return False

    if "/" in path or "\\" in path:
        return False

    if path.startswith("."):
        return False

    if len(path.split(".")) > 2:
        return False

    return True

@app.route('/img')
def img():
    """
    Serves an image file from the UPLOAD_FOLDER.
    """
    filename = request.args.get('file')

    if not filename:
        return "Filename parameter is missing", 400

    if not is_safe_path(filename):
        return "Invalid filename", 400

    filename = secure_filename(filename) # Sanitize filename

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(filepath):
        return "File not found", 404

    try:
        # Check file size before opening
        file_size = os.path.getsize(filepath)
        if file_size > MAX_FILE_SIZE:
            return "File size exceeds the limit", 413

        return send_file(filepath, mimetype='image/jpeg') # Adjust mimetype as needed

    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        print(f"Error serving file: {e}")
        return "Internal Server Error", 500


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handles file uploads.  This is an example of how to securely handle file uploads.
    """
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Check file size before saving
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0, 0) # Reset file pointer

        if file_length > MAX_FILE_SIZE:
            return "File size exceeds the limit", 413

        try:
            file.save(filepath)
            return 'File uploaded successfully'
        except Exception as e:
            print(f"Error saving file: {e}")
            return "Internal Server Error", 500
    else:
        return 'Invalid file type', 400

if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)

