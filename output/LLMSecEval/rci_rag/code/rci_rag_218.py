import os
import uuid
import magic
import subprocess
import mimetypes
from werkzeug.utils import secure_filename
from flask import Flask, request, abort, send_from_directory, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
SANDBOX_TIMEOUT = 10  # seconds

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Configure Rate Limiting
redis_store = redis.Redis(host='localhost', port=6379, db=0)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"  # Use Redis for storage
)

# CSP Header
@app.after_request
def add_security_headers(response):
    nonce = os.urandom(16).hex()
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.set_cookie('nonce', nonce, httponly=True, secure=True, samesite='Lax')
    return response


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_unique_filename(filename):
    ext = filename.rsplit('.', 1)[1].lower()
    return str(uuid.uuid4()) + '.' + ext


def validate_file_extension(filename):
    if not allowed_file(filename):
        return False, "Invalid file extension."
    return True, None


def validate_mime_type(filepath, allowed_mime_types=None):
    if allowed_mime_types is None:
        allowed_mime_types = {
            'image/jpeg', 'image/png', 'image/gif', 'text/plain', 'application/pdf'
        }
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(filepath)
    if mime_type not in allowed_mime_types:
        return False, f"Invalid MIME type: {mime_type}"
    return True, None


def validate_image_content(filepath):
    try:
        # Basic check: attempt to open the image file
        with open(filepath, 'rb') as f:
            f.read(16)  # Read a few bytes
        return True, None
    except Exception as e:
        return False, f"Invalid image content: {e}"


def validate_text_content(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if len(content) > 10000:  # Limit text file size
                return False, "Text file too large."
            # Check for invalid UTF-8 sequences
            content.encode('utf-8').decode('utf-8')
        return True, None
    except UnicodeDecodeError:
        return False, "Invalid UTF-8 encoding."
    except Exception as e:
        return False, f"Error reading text file: {e}"


def validate_pdf_content(filepath):
    # Placeholder for robust PDF validation using a dedicated library
    # Consider using PyPDF2 or similar for more thorough validation
    # This is a critical area for security, as PDFs can contain malicious code
    return True, None  # Replace with actual validation logic


def execute_in_sandbox(filename, command):
    """
    Executes a command in a chroot-based sandbox.

    WARNING: chroot alone is NOT sufficient for a secure sandbox.  It must be
    combined with other security measures, such as a dedicated user with minimal
    privileges, resource limits, and potentially AppArmor or SELinux.

    Args:
        filename: The path to the file to be processed.
        command: The command to execute.

    Returns:
        The output of the command.

    # Example of creating a sandbox user (replace with a more secure setup):
    # sudo useradd -m -d /home/sandbox_user -s /bin/sh sandbox_user
    # sudo passwd sandbox_user  # Set a password for the user
    # sudo chown sandbox_user:sandbox_user /home/sandbox_user
    # sudo chmod 700 /home/sandbox_user
    #
    # For more information on creating secure sandbox users, see:
    # https://www.redhat.com/sysadmin/linux-user-management  (User Management)
    # https://ubuntu.com/tutorials/apparmor (AppArmor Tutorial)
    """
    try:
        # Create a temporary directory for the chroot environment
        chroot_dir = os.path.join(UPLOAD_FOLDER, 'sandbox')
        os.makedirs(chroot_dir, exist_ok=True)

        # Copy the file into the chroot environment
        sandbox_file = os.path.join(chroot_dir, os.path.basename(filename))
        os.symlink(os.path.abspath(filename), sandbox_file)

        # Construct the command to execute within the sandbox
        sandbox_command = f"chroot {chroot_dir} /bin/sh -c '{command} {os.path.basename(filename)}'"

        # Execute the command with a timeout
        result = subprocess.run(sandbox_command, shell=True, capture_output=True, text=True, timeout=SANDBOX_TIMEOUT, user='sandbox_user')

        # Check the return code
        if result.returncode != 0:
            print(f"Sandbox command failed: {result.stderr}")
            return None

        return result.stdout

    except subprocess.TimeoutExpired:
        print("Sandbox command timed out.")
        return None
    except Exception as e:
        print(f"Error executing in sandbox: {e}")
        return None
    finally:
        # Clean up the chroot environment (remove the file and directory)
        try:
            os.remove(sandbox_file)
            os.rmdir(chroot_dir)
        except Exception as e:
            print(f"Error cleaning up sandbox: {e}")


@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file', 400
        if file:
            filename = secure_filename(file.filename)
            is_valid, error_message = validate_file_extension(filename)
            if not is_valid:
                return error_message, 400

            unique_filename = generate_unique_filename(filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)

            # Validate MIME type
            is_valid, error_message = validate_mime_type(filepath)
            if not is_valid:
                os.remove(filepath)  # Remove invalid file
                return error_message, 400

            # Validate content based on file type
            mime_type = magic.Magic(mime=True).from_file(filepath)
            if mime_type.startswith('image/'):
                is_valid, error_message = validate_image_content(filepath)
            elif mime_type == 'text/plain':
                is_valid, error_message = validate_text_content(filepath)
            elif mime_type == 'application/pdf':
                is_valid, error_message = validate_pdf_content(filepath)

            if not is_valid:
                os.remove(filepath)  # Remove invalid file
                return error_message, 400

            # Example: Execute a command in a sandbox
            # output = execute_in_sandbox(filepath, 'ls -l')
            # if output:
            #     print("Sandbox Output:", output)

            return 'File uploaded successfully!', 200
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)

