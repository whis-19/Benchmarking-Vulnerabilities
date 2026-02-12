import os
import secrets
import functools
from flask import Flask, request, render_template, session, redirect, url_for, abort, send_from_directory
from werkzeug.utils import secure_filename
import uuid
import magic  # Import the magic library
import logging  # Import the logging module

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Session cookie configuration (important for security!)
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Or 'Strict'

# CSP Header
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self';"
    return response

# CSRF Token Generation and Validation
def generate_csrf_token():
    session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    return 'csrf_token' in session and session['csrf_token'] == token

def csrf_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or not validate_csrf_token(token):
                logging.warning("CSRF token validation failed")  # Log the failure
                abort(400)  # Bad Request - CSRF token invalid
        return fn(*args, **kwargs)
    return wrapper

# Secure File Upload Handling
def allowed_file(filename):
    # Reject files with multiple extensions
    return filename.count('.') == 1 and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_content_type(file_path: str) -> bool:
    """
    Checks if the file content type is allowed based on its magic number.
    """
    try:
        mime = magic.Magic(mime=True)
        content_type = mime.from_file(file_path)
        # Define allowed content types based on your needs
        allowed_content_types = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain']
        if content_type in allowed_content_types:
            return True
        else:
            logging.warning(f"Detected content type: {content_type} - Not allowed")  # Log the rejected type
            return False
    except Exception as e:
        logging.error(f"Error determining content type: {e}")
        return False  # Treat as unsafe in case of error

@app.route('/upload', methods=['GET', 'POST'])
@csrf_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('upload.html', message='No file part', csrf_token=generate_csrf_token())
        file = request.files['file']
        if file.filename == '':
            return render_template('upload.html', message='No selected file', csrf_token=generate_csrf_token())
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = str(uuid.uuid4()) + "_" + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            if not os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
                logging.warning("Directory traversal attempt detected during file upload")
                return render_template('upload.html', message='Invalid file path', csrf_token=generate_csrf_token())

            file.save(filepath)

            if not is_safe_content_type(filepath):
                os.remove(filepath)  # Remove the file if it's not a safe type
                logging.warning(f"Unsafe file content type detected for {filename}. File removed.")
                return render_template('upload.html', message='Unsafe file content type', csrf_token=generate_csrf_token())

            logging.info(f"File {filename} uploaded successfully")
            return render_template('upload.html', message='File uploaded successfully', csrf_token=generate_csrf_token())
        else:
            return render_template('upload.html', message='Invalid file type', csrf_token=generate_csrf_token())
    return render_template('upload.html', csrf_token=generate_csrf_token())

# Securely Serving Files
@app.route('/uploads/<name>')
def download_file(name):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], name)
    if not os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        logging.warning("Directory traversal attempt detected during file download")
        abort(400)

    try:
        return send_from_directory(app.config["UPLOAD_FOLDER"], name)
    except FileNotFoundError:
        abort(404)

# Secure Input Validation and Sanitization
def sanitize_input(input_string: str) -> str:
    """
    Basic sanitization - replace potentially harmful characters.
    This is for *output* sanitization (escaping before rendering).
    More robust sanitization might be needed depending on the context.
    """
    return input_string.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

def sanitize_for_database(input_string: str, db_connection) -> str:
    """
    Example using parameterized queries to prevent SQL injection.
    This is just an example.  The specific method depends on your database library.
    NEVER use string concatenation to build SQL queries.
    """
    # Example using psycopg2 (PostgreSQL)
    # cur = db_connection.cursor()
    # cur.execute("SELECT * FROM users WHERE username = %s", (input_string,))
    # return cur.fetchone()
    return db_connection.escape_string(input_string) # Generic example - replace with your DB library's method

def validate_integer(input_string: str) -> int | None:
    """
    Validates that the input is an integer.  Returns the integer if valid,
    otherwise returns None.
    """
    try:
        return int(input_string)
    except ValueError:
        return None

# The Core Functionality
id_sequence = [10, 20, 30, 40, 50]  # Example array - DO NOT HARDCODE SENSITIVE DATA

def getValueFromArray(arr: list, size: int, index: int) -> int:
    """
    Returns the value at the given index in the array.
    Handles potential out-of-bounds errors securely.
    """
    if not isinstance(arr, list):
        raise TypeError("arr must be a list")

    if not isinstance(size, int):
        raise TypeError("size must be an integer")

    if not isinstance(index, int):
        raise TypeError("index must be an integer")

    if index < 0 or index >= size:
        raise IndexError("Index out of bounds")

    return arr[index]

@app.route('/', methods=['GET', 'POST'])
def main():
    if request.method == 'POST':
        index_str = request.form.get('index')

        if not index_str:
            return render_template('index.html', error="Index is required", csrf_token=generate_csrf_token())

        index = validate_integer(index_str)
        if index is None:
            return render_template('index.html', error="Invalid index (must be an integer)", csrf_token=generate_csrf_token())

        try:
            result = getValueFromArray(id_sequence, len(id_sequence), index)
            escaped_result = sanitize_input(str(result))
            return render_template('index.html', result=escaped_result, csrf_token=generate_csrf_token())
        except (TypeError, IndexError) as e:
            logging.exception("Error in main route")  # Log the exception
            return render_template('index.html', error=str(e), csrf_token=generate_csrf_token())

    return render_template('index.html', csrf_token=generate_csrf_token())

@app.errorhandler(400)
def bad_request(e):
    logging.warning("Bad Request - Invalid CSRF token")
    return "Bad Request - Invalid CSRF token", 400

@app.errorhandler(404)
def page_not_found(e):
    logging.warning("Page not found")
    return "Page not found", 404

@app.errorhandler(413)
def request_entity_too_large(e):
    logging.warning("Request Entity Too Large")
    return "File too large", 413

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

