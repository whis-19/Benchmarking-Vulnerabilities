import os
import secrets
import logging
from flask import Flask, request, redirect, url_for, send_from_directory, render_template, abort
from werkzeug.utils import secure_filename
import magic  # Install with: pip install python-magic
import mimetypes
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from defusedxml import ElementTree

# Configuration
UPLOAD_FOLDER = 'uploads'  # Directory to store uploaded files
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg'}  # Allowed file extensions
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Maximum file size (16MB)
MAX_FILENAME_LENGTH = 200 # Maximum filename length after sanitization

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a strong secret key

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Adjust limits as needed
)

# Configure logging
logging.basicConfig(filename='upload.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize magic
try:
    mime = magic.Magic(mime=True)
except magic.MagicException as e:
    logging.warning(f"Error initializing magic: {e}. Content-type checking will be less reliable.")
    mime = None


def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_safe_content_type(filepath):
    """Check if the file content type is safe using libmagic."""
    if mime is None:
        logging.warning("Skipping content-type check because libmagic is not available.")
        return True  # If magic is not available, allow all files (less secure)

    try:
        content_type = mime.from_file(filepath)
        logging.info(f"Detected content type: {content_type} for {filepath}")

        # Define allowed content types more strictly.  Adjust as needed.
        allowed_content_types = [
            'image/jpeg',
            'image/png',
            'image/gif',
            'application/pdf',
            'text/plain',
            'image/jpg', # Sometimes magic returns image/jpg
            'image/svg+xml'
        ]

        if content_type not in allowed_content_types:
            return False

        # Additional SVG sanitization if SVG is allowed
        if content_type == 'image/svg+xml':
            try:
                # Sanitize SVG using defusedxml
                with open(filepath, 'r') as f:
                    xml_string = f.read()
                ElementTree.fromstring(xml_string)  # This will raise an exception if malicious
                logging.info(f"SVG file {filepath} passed sanitization.")
            except Exception as e:
                logging.warning(f"SVG file {filepath} failed sanitization: {e}")
                return False

        return True
    except Exception as e:
        logging.error(f"Error determining content type for {filepath}: {e}")
        return False  # Treat as unsafe if there's an error


@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit uploads to 5 per minute per IP
def upload_file():
    """Handles file uploads."""
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request.")
            return render_template('upload.html', error='No file part')

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected.")
            return render_template('upload.html', error='No selected file')

        if file and allowed_file(file.filename):
            # Secure filename to prevent path traversal vulnerabilities
            filename = secure_filename(file.filename)

            # Validate filename length
            if len(filename) > MAX_FILENAME_LENGTH:  # Adjust the maximum length as needed
                logging.warning(f"Filename too long: {filename}")
                return render_template('upload.html', error=f'Filename is too long (max {MAX_FILENAME_LENGTH} characters)')

            # Generate a unique filename to prevent overwriting
            unique_filename = secrets.token_hex(8) + "_" + filename

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            # Double-check path traversal
            filepath = os.path.normpath(filepath)
            if not filepath.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
                logging.error(f"Path traversal detected: {filepath}")
                return render_template('upload.html', error='Invalid file path')

            # Save the file
            try:
                file.save(filepath)
                logging.info(f"File saved to {filepath}")

                # Check content type
                if not is_safe_content_type(filepath):
                    os.remove(filepath)  # Remove the file if it's not safe
                    logging.warning(f"Unsafe content type detected for {filepath}. File removed.")
                    return render_template('upload.html', error='Unsafe file content')

            except Exception as e:
                logging.exception(f"Error saving file: {e}")  # Log the full exception
                if os.path.exists(filepath): # Check if file was created before error
                    os.remove(filepath) # Remove potentially corrupted file
                return render_template('upload.html', error='Error saving file')

            # Redirect to the uploaded file's URL
            return redirect(url_for('download_file', name=unique_filename))
        else:
            logging.warning(f"Invalid file type: {file.filename}")
            return render_template('upload.html', error='Invalid file type')

    return render_template('upload.html', error=None)


@app.route('/uploads/<name>')
def download_file(name):
    """Serves the uploaded file for download."""
    try:
        # Construct the full file path
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], name)

        # Check if the file exists
        if not os.path.isfile(filepath):
            logging.warning(f"File not found: {name}")
            abort(404)  # Or return a custom error page

        # Determine the MIME type
        mime_type, _ = mimetypes.guess_type(filepath)
        if mime_type is None:
            mime_type = 'application/octet-stream'  # Default binary type

        logging.info(f"Serving file: {name} with MIME type: {mime_type}")

        # Send the file with appropriate headers
        response = send_from_directory(
            app.config["UPLOAD_FOLDER"],
            name,
            as_attachment=True,  # Force download
            mimetype=mime_type
        )

        # Set security headers
        response.headers['Content-Disposition'] = f'attachment; filename="{name}"'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    except FileNotFoundError:
        logging.error(f"File not found: {name}")
        abort(404)  # Or return a custom error page
    except Exception as e:
        logging.exception(f"Error serving file {name}: {e}")
        abort(500)  # Internal Server Error


@app.errorhandler(413)
def request_entity_too_large(e):
    """Handles the case where the file size exceeds the limit."""
    logging.warning("File size exceeds the limit.")
    return render_template('upload.html', error=f'File size exceeds the limit ({MAX_CONTENT_LENGTH / (1024 * 1024)}MB)')


@app.errorhandler(404)
def not_found_error(error):
    logging.error(f"404 Error: {error}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"500 Error: {error}")
    return render_template('500.html'), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)  # Don't use debug mode in production

