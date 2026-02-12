import os
import uuid
import mimetypes
from functools import wraps
from flask import Flask, request, send_file, abort, redirect, url_for, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import secrets
import magic
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Generate a strong secret key and store it securely (e.g., environment variable)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    # Fallback to a randomly generated key, but this is NOT suitable for production
    SECRET_KEY = secrets.token_hex(24)
    print("WARNING: Using a randomly generated secret key.  This is NOT suitable for production.")
app.secret_key = SECRET_KEY

# Configure session security
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF

# Enable CSRF protection
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define the directory where images are stored.  Crucially, make this configurable
IMAGE_DIR = os.environ.get("IMAGE_DIR", "images")  # Default to "images" if not set

# Ensure the image directory exists
os.makedirs(IMAGE_DIR, exist_ok=True)

# File size limit (in bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Dummy user database (replace with a real database)
# In a real application, use a database and a proper ORM (e.g., SQLAlchemy)
users = {
    "admin": generate_password_hash("password")  # Store hashed passwords!
}

# Account lockout settings
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

login_attempts = {}  # Store login attempts per username


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('username') is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    global login_attempts  # Access the global dictionary

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check for account lockout
        if username in login_attempts and login_attempts[username]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            time_elapsed = time.time() - login_attempts[username]['last_attempt']
            if time_elapsed < LOCKOUT_DURATION:
                remaining_time = LOCKOUT_DURATION - time_elapsed
                return render_template('login.html', error=f'Account locked. Try again in {int(remaining_time)} seconds.')
            else:
                # Reset login attempts if lockout duration has passed
                login_attempts[username]['attempts'] = 0

        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            # Reset login attempts on successful login
            if username in login_attempts:
                del login_attempts[username]
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            # Increment login attempts
            if username not in login_attempts:
                login_attempts[username] = {'attempts': 0, 'last_attempt': 0}
            login_attempts[username]['attempts'] += 1
            login_attempts[username]['last_attempt'] = time.time()

            logger.warning(f"Failed login attempt for user: {username}")
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/')
@login_required
def index():
    return "Logged in as " + session['username'] + "<br><a href='/upload'>Upload</a> <a href='/logout'>Logout</a>"


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file part", 400
        file = request.files['file']
        if file.filename == '':
            return "No selected file", 400

        filename = secure_filename(file.filename)  # Sanitize filename

        if not filename:
            return "Invalid filename", 400

        # Enforce filename length limit
        if len(filename) > 255:  # Example limit
            return "Filename too long. Maximum length is 255 characters.", 400

        # Validate file content type (using libmagic - more robust than extension or magic bytes)
        file_content = file.read()
        file.seek(0)  # Reset file pointer after reading

        try:
            mime = magic.from_buffer(file_content, mime=True)
            if not mime.startswith('image/'):
                return "Invalid file type. Only images are allowed.", 400
        except magic.MagicException as e:
            logger.error(f"Error determining file type: {e}")
            return "Error: Could not determine file type.", 500

        if file:
            # Generate a unique filename
            unique_filename = str(uuid.uuid4())
            file_extension = os.path.splitext(filename)[1]  # Use sanitized filename
            filepath = os.path.join(IMAGE_DIR, unique_filename + file_extension)

            # Save the file
            try:
                file.save(filepath)
            except Exception as e:
                logger.error(f"Error saving file: {e}")
                return "Error: Could not save file.", 500

            # Store the mapping in your database (not shown here)
            # Example:  db.insert_image(unique_filename, file_extension, session['username'])

            return f"File uploaded successfully.  Unique filename: {unique_filename + file_extension}"
    return render_template('upload.html')  # Create an upload.html template


import time

@app.route("/img/<filename>")
@login_required
def img(filename):
    """Serves images based on the unique filename."""

    # Sanitize the filename to prevent path traversal
    filename = secure_filename(filename)
    if ".." in filename or "/" in filename or "\\" in filename:
        logger.warning(f"Possible path traversal attempt with filename: {filename}")
        abort(400)  # Or return a 404

    filepath = os.path.join(IMAGE_DIR, filename)

    if not os.path.isfile(filepath):
        abort(404)

    try:
        mime_type = magic.from_file(filepath, mime=True)
    except magic.MagicException as e:
        logger.error(f"Error determining MIME type: {e}")
        mime_type = 'application/octet-stream'  # Default to binary download

    try:
        return send_file(filepath, mimetype=mime_type)
    except FileNotFoundError:
        abort(404)
    except Exception as e:
        logger.error(f"Error serving image: {e}")
        return "Error: Internal server error.", 500


if __name__ == "__main__":
    # Create dummy templates
    with open("templates/login.html", "w") as f:
        f.write("""
        <form method="post">
            {{ csrf_token() }}
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
            {% if error %}
                <p style="color: red;">{{ error }}</p>
            {% endif %}
        </form>
        """)
    with open("templates/upload.html", "w") as f:
        f.write("""
        <form method="post" enctype="multipart/form-data">
            {{ csrf_token() }}
            <input type="file" name="file">
            <button type="submit">Upload</button>
        </form>
        """)

    # Create a dummy image for testing
    with open(os.path.join(IMAGE_DIR, "test.jpg"), "wb") as f:
        f.write(b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xDB\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x11\x11\x1a\x1f\x1f\x1a\x17\x1b\x1f\x18\x18#\x22\x27\x29\x27\x22#$%$+\x1e\x1f((77,,,,\x01\t\t\t\x0c\x0b\x0c\x18\r\r\x182!\x1c!2OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO\xFF\xC0\x00\x11\x08\x00\x01\x00\x01\x03\x01\"\x00\x02\x11\x01\x03\x11\x01\xFF\xC4\x00\x1F\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xFF\xC4\x00\xB5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01\x7D\x01\x02\x03\x00\x04\x11\x05\x12!1A\x06\x13Qa\x07\"q\x142\x81\x91\xA1\x08#B\xB1\xC1\x15R\xD1\xF0$br\x82\x92\xA2\xB2\xC2\xE1t\x163CS\xF1!\x17\x04\x05\x18\x19\x1A%s\x83\x93\xA3\xB3\xC3\xD3\xE3$4\x1F\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xFF\xC4\x00\x1F\x01\x00\x03\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xFF\xC4\x00\xB5\x11\x00\x02\x01\x02\x04\x04\x03\x04\x07\x05\x04\x04\x00\x01\x02w\x00\x01\x02\x03\x11\x04\x05!1\x12AQ\x06\x13aq\"2\x81\x07\x91\xA1\x14B#r\xC1\xD1$3\x82\x92\xA2\xB2\xE2\xF1%4\x15R\x83\x93\xA3\xB3\xC3\xD3\xE3\xF0\x16CSs\x84\x94\xA4\xB4\xC4\xD4\xE4\xF4\x175\x85\x95\xA5\xB5\xC5\xD5\xE5\xF5\x186t\x86\x96\xA6\xB6\xC6\xD6\xE6\xF6'7GWgw\x87\x97\xA7\xB7\xC7\xD7\xE7\xF7\x198HXhx\x88\x98\xA8\xB8\xC8\xD8\xE8\xF8\x1A9IYiy\x89\x99\xA9\xB9\xC9\xD9\xE9\xF9\x1AJZjz\x8A\x9A\xAA\xBA\xCA\xDA\xEA\xFA\x00\xFF\xDA\x00\x08\x01\x01\x00\x00?\x00\xD2\xFF\xD9")  # Replace with actual image data

    app.run(debug=False)  # Disable debug mode in production!

