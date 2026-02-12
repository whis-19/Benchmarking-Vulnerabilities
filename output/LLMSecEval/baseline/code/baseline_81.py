import os
import uuid
from flask import Flask, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}  # Only allow PDF files
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Limit file size to 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """
    Handles file uploads.
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
            # Secure filename and generate a unique filename to prevent overwrites
            filename = secure_filename(file.filename)
            unique_filename = str(uuid.uuid4()) + "_" + filename  # Add UUID for uniqueness
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            # Save the file
            try:
                file.save(filepath)
            except Exception as e:
                print(f"Error saving file: {e}")
                return "Error saving file. Please try again."

            # Redirect to a page showing the uploaded file (optional)
            return redirect(url_for('download_file', name=unique_filename))

    return '''
    <!doctype html>
    <html>
    <head>
        <title>Upload PDF</title>
    </head>
    <body>
        <h1>Upload PDF File</h1>
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
    Serves the uploaded file (optional).  This is just an example and might not be needed.
    Consider carefully if you need to expose the uploaded files directly.
    """
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)


if __name__ == '__main__':
    #  IMPORTANT:  Never run this in production with debug=True.
    #  It exposes sensitive information and can be a security risk.
    app.run(debug=True)

