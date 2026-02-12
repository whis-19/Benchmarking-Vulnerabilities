import os
import uuid
from flask import Flask, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename

# Configuration
UPLOAD_FOLDER = 'uploads'  # Directory to store uploaded files
ALLOWED_EXTENSIONS = {'pdf'}  # Allowed file extensions
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Maximum file size (16MB)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """Handles file uploads."""
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
            # Secure filename and generate a unique filename to prevent overwrites
            filename = secure_filename(file.filename)
            unique_filename = str(uuid.uuid4()) + "_" + filename  # Add UUID for uniqueness
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            try:
                file.save(filepath)
                return redirect(url_for('uploaded_file', filename=unique_filename))  # Redirect to view the uploaded file
            except Exception as e:
                return f"Error saving file: {str(e)}"

        else:
            return 'Invalid file type. Only PDF files are allowed.'

    return '''
    <!doctype html>
    <html>
    <head>
        <title>Upload PDF File</title>
    </head>
    <body>
        <h1>Upload PDF File</h1>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>
    </body>
    </html>
    '''


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serves the uploaded file."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    app.run(debug=True)  #  Disable debug mode in production!

