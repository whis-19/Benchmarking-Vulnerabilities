import os
import uuid
from flask import Flask, request, render_template, send_from_directory
from werkzeug.utils import secure_filename
import logging
import html

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration -  Crucially, store uploads *outside* the web document root.
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'pdf'}  # Only allow PDF files
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Limit file size to 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure the upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request")
            return render_template('upload.html', error='No file part')

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected")
            return render_template('upload.html', error='No file selected')

        if file and allowed_file(file.filename):
            # Secure the filename to prevent path traversal attacks
            filename = secure_filename(file.filename)

            # Generate a unique filename to prevent overwrites and potential information disclosure
            unique_filename = str(uuid.uuid4()) + "_" + filename

            # Construct the full path to save the file
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            # Save the file
            try:
                file.save(filepath)
                logging.info(f"File saved to: {filepath}")

                # Sanitize the filename for display in the HTML (important!)
                display_filename = html.escape(filename)  # Encode special characters

                return render_template('upload.html', success=f'File "{display_filename}" uploaded successfully!')

            except Exception as e:
                logging.exception("Error saving file:")
                return render_template('upload.html', error=f'Error saving file: {str(e)}')

        else:
            logging.warning("Invalid file type")
            return render_template('upload.html', error='Invalid file type. Only PDF files are allowed.')

    return render_template('upload.html')


# Serve static files (for demonstration purposes only - in production, use a dedicated web server)
@app.route('/uploads/<name>')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)


@app.errorhandler(413)
def request_entity_too_large(error):
    logging.error("File size exceeded maximum limit.")
    return render_template('upload.html', error='File size exceeded the maximum limit of 16MB.'), 413


if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!  It can expose sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

