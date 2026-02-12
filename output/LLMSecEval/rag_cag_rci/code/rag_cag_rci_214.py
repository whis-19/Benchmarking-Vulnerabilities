import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong secret key

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure upload folder exists and has correct permissions
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.chmod(UPLOAD_FOLDER, 0o750)  # Example: Owner read/write/execute, group read/execute

# Utility Functions

def generate_csrf_token():
    session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    return 'csrf_token' in session and session['csrf_token'] == token

def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or not validate_csrf_token(token):
                return render_template('error.html', message="CSRF token is invalid."), 400
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """
    Sanitizes a filename to prevent path traversal and other attacks.
    """
    filename = secure_filename(filename)  # Werkzeug's secure_filename
    if filename is None or filename == "":
        return None

    if ".." in filename or "/" in filename or "\\" in filename:
        return None

    if filename.count(".") > 1:
        return None

    return filename

def validate_filepath(filepath):
    """
    Validates a filepath against an allowlist of known good patterns.
    This example uses a very simple allowlist: only filenames are allowed.
    More complex allowlists can be implemented as needed.
    """
    if "/" in filepath or "\\" in filepath or ".." in filepath:
        return False

    if filepath.count(".") > 1:
        return False

    return True

# Routes

@app.route('/', methods=['GET'])
def index():
    csrf_token = generate_csrf_token()
    return render_template('index.html', csrf_token=csrf_token)

@app.route('/upload', methods=['POST'])
@csrf_required
def upload_file():
    if 'file' not in request.files:
        return render_template('error.html', message="No file part"), 400
    file = request.files['file']
    if file.filename == '':
        return render_template('error.html', message="No selected file"), 400

    if file and allowed_file(file.filename):
        filename = sanitize_filename(file.filename)
        if not filename:
            return render_template('error.html', message="Invalid filename"), 400

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        if not validate_filepath(filename):
            return render_template('error.html', message="Invalid filepath"), 400

        try:
            file.save(filepath)
            os.chmod(filepath, 0o640)  # Example: Owner read/write, group read
            return render_template('success.html', filename=filename)
        except Exception as e:
            print(f"Error saving file: {e}")  # Log the error
            return render_template('error.html', message="Error saving file"), 500
    else:
        return render_template('error.html', message="Invalid file type. Only PDF files are allowed."), 400

@app.route('/uploads/<filename>')
def download_file(filename):
    """
    Serves files from the upload directory.  This route should be protected
    with authentication and authorization in a real application.
    """
    try:
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)
    except FileNotFoundError:
        return render_template('error.html', message="File not found"), 404

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template('error.html', message='File size exceeds the limit of 16MB.'), 413

# Error handling
@app.errorhandler(Exception)
def handle_exception(e):
    """Handles all unhandled exceptions."""
    print(f"Unhandled exception: {e}")  # Log the exception
    return render_template('error.html', message="An unexpected error occurred."), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

