import os
import secrets
from flask import Flask, request, redirect, url_for, send_from_directory, render_template
from werkzeug.utils import secure_filename

# Configuration
UPLOAD_FOLDER = 'uploads'  # Directory to store uploaded files
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Allowed file extensions
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Maximum file size (16MB)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a strong secret key

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
            return render_template('upload.html', error='No file part')

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return render_template('upload.html', error='No selected file')

        if file and allowed_file(file.filename):
            # Secure filename to prevent path traversal vulnerabilities
            filename = secure_filename(file.filename)

            # Generate a unique filename to prevent overwriting
            unique_filename = secrets.token_hex(8) + "_" + filename

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            # Save the file
            try:
                file.save(filepath)
            except Exception as e:
                print(f"Error saving file: {e}")  # Log the error
                return render_template('upload.html', error='Error saving file')

            # Redirect to the uploaded file's URL
            return redirect(url_for('download_file', name=unique_filename))
        else:
            return render_template('upload.html', error='Invalid file type')

    return render_template('upload.html', error=None)


@app.route('/uploads/<name>')
def download_file(name):
    """Serves the uploaded file for download."""
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)


@app.errorhandler(413)
def request_entity_too_large(e):
    """Handles the case where the file size exceeds the limit."""
    return render_template('upload.html', error='File size exceeds the limit (16MB)')


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)  # Don't use debug mode in production

