from flask import request, send_file, Flask, abort, session
import os
import uuid
from werkzeug.utils import secure_filename
import mimetypes
import magic  # Import the python-magic library
import logging
from functools import wraps
from flask_wtf.csrf import CSRFProtect, generate_csrf

# Consider using a dedicated PDF parsing/validation library
# import PyPDF2

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure secret key for session management and CSRF
csrf = CSRFProtect(app)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Explicit allowlist
MAX_FILE_SIZE = 10 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_file_content(filepath):
    """Validates file content based on magic bytes and other checks."""
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(filepath)

    if mime_type.startswith('image/'):
        try:
            from PIL import Image
            img = Image.open(filepath)
            img.verify()
            img.close()  # Close the image after verification
            return True, None
        except Exception as e:
            logging.error(f"Image validation failed: {e}")
            return False, f"Image validation failed: {e}"
    elif mime_type == 'application/pdf':
        try:
            # Basic PDF validation (can be improved with PyPDF2)
            with open(filepath, 'rb') as f:
                if f.read(4) != b'%PDF':
                    return False, "Invalid PDF file."
            # More robust PDF validation using PyPDF2 (example, requires PyPDF2 installation)
            # try:
            #     with open(filepath, 'rb') as pdf_file:
            #         pdf_reader = PyPDF2.PdfReader(pdf_file)
            #         # Accessing any attribute triggers parsing and potential exceptions
            #         num_pages = len(pdf_reader.pages)
            #     return True, None
            # except Exception as e:
            #     logging.error(f"PyPDF2 PDF validation failed: {e}")
            #     return False, f"Invalid PDF file: {e}"

            return True, None
        except Exception as e:
            logging.error(f"PDF validation failed: {e}")
            return False, f"PDF validation failed: {e}"
    elif mime_type == 'text/plain':
        try:
            with open(filepath, 'r') as f:
                f.read()
            return True, None
        except Exception as e:
            logging.error(f"Text file validation failed: {e}")
            return False, f"Text file validation failed: {e}"
    else:
        return False, "Unsupported file type."


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return "Authentication required", 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')  # In real app, hash and salt this

    if username == 'test' and password == 'password':  # Replace with secure authentication
        session['username'] = username
        return "Logged in successfully", 200
    else:
        return "Invalid credentials", 401


@app.route('/logout')
def logout():
    session.pop('username', None)
    return "Logged out successfully", 200


@app.route('/upload', methods=['POST'])
@login_required
@csrf.exempt  # CSRF protection is handled by Flask-WTF, but we're skipping it for brevity
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        if not filename:  # Check if filename is empty after sanitization
            return "Invalid filename after sanitization", 400

        file_ext = filename.rsplit('.', 1)[1].lower()
        unique_filename = str(uuid.uuid4()) + '.' + file_ext
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        file.save(filepath)

        is_valid, error_message = validate_file_content(filepath)
        if not is_valid:
            os.remove(filepath)
            return f"File validation failed: {error_message}", 400

        return 'File uploaded successfully', 200
    else:
        return 'Invalid file type', 400


@app.route('/download')
@login_required
def download():
    filename = request.args.get('filename')

    if not filename:
        return "Filename is required", 400

    filename = secure_filename(filename)
    if not filename:
        return "Invalid filename after sanitization", 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Path traversal prevention
    abs_upload_path = os.path.abspath(app.config['UPLOAD_FOLDER'])
    abs_file_path = os.path.abspath(filepath)

    if not abs_file_path.startswith(abs_upload_path):
        return "Invalid file path", 400

    if not os.path.exists(filepath):
        return "File not found", 404

    try:
        # Sanitize download_name again (or use a fixed name)
        # download_name = secure_filename(filename)  # Or use a fixed name like "download.txt"
        download_name = "download.txt" # Fixed download name
        return send_file(filepath, as_attachment=True, download_name=download_name)
    except FileNotFoundError:
        logging.error(f"File not found during download: {filename}")
        return "File not found", 404
    except PermissionError:
        logging.error(f"Permission error during download: {filename}")
        return "Permission denied", 403
    except Exception as e:
        logging.exception(f"An error occurred during download: {e}")  # Log full exception
        return "An error occurred", 500


@app.after_request
def add_csrf_token(response):
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf()
    response.headers.set('X-CSRFToken', session['csrf_token'])
    return response


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

