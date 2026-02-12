from flask import Flask, request, redirect, abort
import base64
import os
from werkzeug.utils import secure_filename
import re

app = Flask(__name__)

UPLOAD_FOLDER = './pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_path(basedir, path, filename):
    """
    Checks if the given path is safe and within the basedir.
    """
    filepath = os.path.join(basedir, path, filename)
    return os.path.abspath(filepath).startswith(os.path.abspath(basedir))

@app.route('/img/upload', methods=['POST'])
def upload_img():
    """
    Get image file from request and save it to ./pictures folder after encoding.
    """
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file', 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)  # Sanitize filename
            if not filename:
                return "Invalid filename", 400

            # Ensure the filename doesn't contain path separators or ".."
            if any(sep in filename for sep in ['/', '\\']):
                return "Invalid filename: Path separators not allowed", 400
            if ".." in filename:
                return "Invalid filename: '..' not allowed", 400

            # Create the upload folder if it doesn't exist
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])

            # Save the file to the upload folder
            try:
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return 'File uploaded successfully', 200
            except Exception as e:
                print(f"Error saving file: {e}")
                return 'Error uploading file', 500
        else:
            return 'Invalid file type', 400

    return '''
    <!doctype html>
    <html>
    <head>
        <title>Upload new File</title>
    </head>
    <body>
        <h1>Upload new File</h1>
        <form method=post enctype=multipart/form-data>
            <input type=file name=file>
            <input type=submit value=Upload>
        </form>
    </body>
    </html>
    ''', 200

if __name__ == '__main__':
    app.run(debug=True)

