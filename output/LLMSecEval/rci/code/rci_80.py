import os
import uuid
import logging
from flask import Flask, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
import PyPDF2

# Configure logging
logging.basicConfig(level=logging.INFO)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_valid_pdf(file_path):
    """
    Performs content-based validation to ensure the uploaded file is a valid PDF.
    Uses PyPDF2 to attempt to read the PDF and checks for errors.
    """
    try:
        with open(file_path, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)
            num_pages = len(pdf.pages)  # Accessing pages triggers parsing
            # Example of keyword search (basic):
            # for page in pdf.pages:
            #     text = page.extract_text()
            #     if "eval" in text.lower():
            #         logging.warning(f"Potentially malicious keyword 'eval' found in: {file_path}")
            #         return False
            return True
    except PyPDF2.errors.PdfReadError:
        logging.warning(f"Invalid PDF structure detected in: {file_path}")
        return False
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return False
    except PermissionError:
        logging.error(f"Permission error accessing: {file_path}")
        return False
    except Exception as e:
        logging.exception(f"Error during PDF validation: {e}")
        return False

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file'
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = str(uuid.uuid4()) + "_" + filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            try:
                file.save(file_path)
                if is_valid_pdf(file_path):
                    return redirect(url_for('download_file', name=unique_filename))
                else:
                    os.remove(file_path)  # Remove invalid file
                    return 'Invalid PDF file'
            except Exception as e:
                logging.exception(f"Error saving or validating file: {e}")
                return 'Error processing file'
    return '''
    <!doctype html>
    <html>
    <head>
        <title>Upload new File</title>
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
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
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

if __name__ == '__main__':
    app.run(debug=True)

