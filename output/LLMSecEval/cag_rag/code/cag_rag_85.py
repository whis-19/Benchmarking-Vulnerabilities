import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Replace with a strong, randomly generated key

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# CSP Header
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';"
    return response

# CSRF Protection
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
                return render_template('error.html', message='CSRF token is invalid.'), 400
        return f(*args, **kwargs)
    return decorated_function

app.jinja_env.globals['csrf_token'] = generate_csrf_token


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """
    Sanitizes a filename to prevent path traversal and other attacks.
    """
    if not filename:
        return None

    filename = secure_filename(filename)  # Basic sanitization

    if filename.count("..") > 0:
        return None  # Reject filenames with ".."

    if "/" in filename or "\\" in filename:
        return None # Reject filenames with path separators

    if filename == "." or filename == "..":
        return None # Reject single path components

    return filename

def upload_file():
    """Handles file uploads with security measures."""
    if 'file' not in request.files:
        return render_template('error.html', message='No file part'), 400

    file = request.files['file']

    if file.filename == '':
        return render_template('error.html', message='No selected file'), 400

    if file and allowed_file(file.filename):
        filename = sanitize_filename(file.filename)
        if not filename:
            return render_template('error.html', message='Invalid filename'), 400

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            file.save(filepath)
            # Set file permissions (restrictive) - important for security
            os.chmod(filepath, 0o600)  # Owner read/write only
            return render_template('success.html', filename=filename)
        except Exception as e:
            print(f"Error saving file: {e}")  # Log the error
            return render_template('error.html', message='Error saving file'), 500
    else:
        return render_template('error.html', message='Invalid file type'), 400


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        return upload_file()
    return render_template('index.html')


@app.errorhandler(413)
def request_entity_too_large(e):
    return render_template('error.html', message='File size exceeds the limit (16MB)'), 413


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

