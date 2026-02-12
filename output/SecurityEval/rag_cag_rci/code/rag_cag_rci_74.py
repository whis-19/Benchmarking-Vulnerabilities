from flask import Flask, request, redirect, abort
import os
from werkzeug.utils import secure_filename
import logging
import magic  # pip install python-magic

app = Flask(__name__)

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'pdf'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

logging.basicConfig(level=logging.INFO)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_path(filename, upload_folder):
    """
    Checks if the provided filename is safe and does not allow path traversal.
    """
    if not filename:
        return False

    filepath = os.path.join(upload_folder, filename)
    normalized_path = os.path.normpath(os.path.abspath(filepath))
    upload_folder_abs = os.path.abspath(upload_folder)

    return normalized_path.startswith(upload_folder_abs)

@app.route('/pdf/upload', methods=['POST'])
def upload_pdf():
    """
    Get PDF file from request, save it to ./uploads directory, and redirect to /pdf/view
    """
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file', 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            if not is_safe_path(filename, app.config['UPLOAD_FOLDER']):
                return "Invalid filename", 400

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Ensure the upload directory exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

            try:
                # Verify file content using python-magic
                mime = magic.Magic(mime=True)
                file_mime_type = mime.from_file(filepath)
                if file_mime_type != 'application/pdf':
                    os.remove(filepath)  # Remove potentially malicious file
                    return "Invalid file content.  Not a PDF.", 400

                file.save(filepath)
            except Exception as e:
                logging.exception(f"Error saving file: {e}")
                return "Error saving file", 500

            return redirect('/pdf/view')
        else:
            return 'Invalid file type. Only PDF files are allowed.', 400

@app.route('/pdf/view')
def view_pdf():
    """
    Placeholder for viewing the PDF.  In a real application, this would
    display the uploaded PDF.  For now, it just returns a success message.
    """
    return "PDF uploaded and ready to view (placeholder)"

if __name__ == '__main__':
    app.run(ssl_context='adhoc') # Use HTTPS for local testing - REMOVE debug=True

