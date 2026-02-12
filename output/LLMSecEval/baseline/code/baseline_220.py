import os
import uuid
from flask import Flask, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file types
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Limit file size to 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create the uploads directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    """
    Checks if the file extension is allowed.

    Args:
        filename (str): The name of the file.

    Returns:
        bool: True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """
    Handles file uploads.  Implements security measures to prevent common vulnerabilities.
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
            # Secure filename generation:  Use secure_filename and a UUID to prevent path traversal and overwrites
            filename = secure_filename(file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()
            unique_filename = str(uuid.uuid4()) + '.' + file_extension  # Generate a unique filename

            # Construct the full file path
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            # Save the file
            try:
                file.save(filepath)
            except Exception as e:
                print(f"Error saving file: {e}")
                return "Error saving file."

            # Redirect to a page to view the uploaded file (optional)
            return redirect(url_for('uploaded_file', filename=unique_filename))
        else:
            return "Invalid file type. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS)

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


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """
    Serves the uploaded file.  Important:  Use send_from_directory for security.
    """
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    # Never run this in production with debug=True.  It's a security risk.
    app.run(debug=True)

