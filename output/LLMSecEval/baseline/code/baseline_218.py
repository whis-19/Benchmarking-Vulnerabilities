import os
import uuid
from flask import Flask, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
import secrets  # For generating secure random filenames

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Restrict allowed file types
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Limit file size to 16MB

# Create the uploads directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH  # Enforce file size limit


def allowed_file(filename):
    """
    Check if the file extension is allowed.

    Args:
        filename (str): The name of the file.

    Returns:
        bool: True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """
    Handles file uploads.

    Returns:
        str: A message indicating the upload status.
    """
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file'

        if file and allowed_file(file.filename):
            # Generate a secure filename using UUID and a random string
            file_extension = file.filename.rsplit('.', 1)[1].lower()
            random_string = secrets.token_hex(8)  # Generate a random hex string
            filename = f"{uuid.uuid4().hex}_{random_string}.{file_extension}"  # Combine UUID, random string, and extension
            filename = secure_filename(filename)  # Sanitize the filename

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            return f'File uploaded successfully.  You can access it at <a href="{url_for("download_file", name=filename)}">{filename}</a>'
        else:
            return 'Invalid file type or file not allowed.'
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
    '''


@app.route('/uploads/<name>')
def download_file(name):
    """
    Serves the uploaded file for download.

    Args:
        name (str): The name of the file to download.

    Returns:
        Response: The file to download.
    """
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)


if __name__ == '__main__':
    #  Never use debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

