import os
import uuid
from flask import Flask, request, redirect, url_for, send_from_directory, make_response
from werkzeug.utils import secure_filename, header_quote
import magic
import logging
#import PyPDF2  # Import if you want to try PDF parsing

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}  # Only allow PDF files
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Limit file size to 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

logging.basicConfig(level=logging.INFO) # Configure logging

def allowed_file(file):
    """
    Checks if the file extension and content type are allowed.
    """
    filename = file.filename
    if not ('.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS):
        logging.warning(f"Invalid file extension for {filename}")
        return False

    try:
        mime = magic.from_buffer(file.read(2048), mime=True)  # Read first 2048 bytes
        file.seek(0)  # Reset file pointer to the beginning
        if mime != 'application/pdf':
            logging.warning(f"MIME type {mime} {mime!r} does not match expected application/pdf for {filename}")
            return False

        # Optional:  Attempt to parse the PDF and check for suspicious content
        # try:
        #     pdf = PyPDF2.PdfReader(file)
        #     # Check for embedded JavaScript, unusual object structures, etc.
        #     # This is a very basic example and needs to be expanded
        #     for page in pdf.pages:
        #         if '/JS' in page:
        #             logging.warning(f"Potential JavaScript found in PDF {filename}")
        #             return False
        #     file.seek(0) # Reset file pointer again
        # except PyPDF2.errors.PdfReadError as e:
        #     logging.warning(f"Error parsing PDF {filename}: {e}")
        #     return False
        # except Exception as e:
        #     logging.exception(f"Unexpected error during PDF parsing for {filename}: {e}")
        #     return False

        return True
    except magic.MagicException as e:
        logging.error(f"Error detecting MIME type for {filename}: {e}")
        return False
    except Exception as e:
        logging.exception(f"Unexpected error during MIME type check for {filename}: {e}") # Log the full traceback
        return False


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

        if file and allowed_file(file):  # Pass the file object to allowed_file
            # Secure filename and generate a unique filename to prevent overwrites
            filename = secure_filename(file.filename) # Sanitize the original filename
            # secure_filename only sanitizes the filename, it does not validate the contents of the file.
            unique_filename = str(uuid.uuid4()) # Use only UUID for filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            # Save the file
            try:
                file.save(filepath)
            except Exception as e:
                logging.error(f"Error saving file: {e}")
                return f"Error saving file: {e}"

            # Redirect to the uploaded file display route (optional)
            return redirect(url_for('uploaded_file', filename=unique_filename))
        else:
            return 'Invalid file type. Only PDF files are allowed.'

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
    Serves the uploaded file.
    """
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    response = make_response(send_from_directory(app.config['UPLOAD_FOLDER'], filename))
    quoted_filename = header_quote(filename)  # Properly escape the filename
    response.headers['Content-Disposition'] = f'inline; filename="{quoted_filename}"'  # Or 'attachment'
    return response


if __name__ == '__main__':
    #  Never run this in production!  Use a proper WSGI server like Gunicorn or uWSGI.
    app.run(debug=True)

