import os
from flask import Flask, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
import logging

# Configuration
UPLOAD_FOLDER = '/var/app/uploads'  # Store outside web document root
ALLOWED_EXTENSIONS = {'pdf'}  # Only allow PDF files
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Limit file size to 16MB

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure the upload directory exists and has proper permissions
try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.chmod(UPLOAD_FOLDER, 0o700)  # Restrict access to the user running the app
except OSError as e:
    logging.error(f"Failed to create or set permissions on upload folder: {e}")
    # Handle the error appropriately, e.g., exit the application
    raise  # Re-raise the exception to stop the app if critical

def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_filename(filename):
    """
    Additional checks beyond secure_filename to prevent path traversal.
    """
    if filename.count('.') > 1:
        logging.warning(f"Filename contains multiple dots: {filename}")
        return False

    if any(sep in filename for sep in ['/', '\\']):
        logging.warning(f"Filename contains path separators: {filename}")
        return False

    if ".." in filename:
        logging.warning(f"Filename contains '..' sequence: {filename}")
        return False

    return True

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request")
            return 'No file part'

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected")
            return 'No selected file'

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            if not is_safe_filename(filename):
                return "Invalid filename.  Please use a filename without special characters or path separators."

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                file.save(filepath)
                logging.info(f"File saved successfully to: {filepath}")
                return redirect(url_for('uploaded_file', filename=filename))
            except Exception as e:
                logging.error(f"Error saving file: {e}")
                return f"Error saving file: {e}"

        else:
            logging.warning(f"File type not allowed: {file.filename}")
            return 'File type not allowed. Only PDF files are accepted.'

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
    Serves the uploaded file (after proper authentication and authorization in a real application).
    This is a placeholder and should be secured in a production environment.
    """
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)
    except Exception as e:
        logging.error(f"Error serving file: {e}")
        return f"Error serving file: {e}"

if __name__ == '__main__':
    #  DO NOT USE `debug=True` IN PRODUCTION!
    #  It can expose sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

