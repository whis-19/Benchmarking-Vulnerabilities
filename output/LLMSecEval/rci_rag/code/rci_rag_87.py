import os
import uuid
import mimetypes
from flask import Flask, request, abort, send_from_directory
from werkzeug.utils import secure_filename
import subprocess
import shutil
import magic  # For more robust MIME type detection
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image  # Import Pillow for image processing
import piexif  # Import piexif for EXIF data manipulation
import PyPDF2  # Import PyPDF2 for PDF processing

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Whitelist extensions
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
MAX_IMAGE_WIDTH = 4000
MAX_IMAGE_HEIGHT = 4000
MAX_FILENAME_LENGTH = 255  # Maximum filename length
MAGIC_DB_MAX_AGE_DAYS = 30 # Maximum age of the magic database in days

# Create the uploads directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example: 200 requests per day, 50 per hour
)

# Security Headers (Example - use Flask-Talisman for more comprehensive handling)
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # HSTS
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Clickjacking protection
    response.headers['X-Content-Type-Options'] = 'nosniff'  # MIME sniffing protection
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; script-src 'self';"  # CSP - adjust as needed
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'  # Referrer policy
    return response


def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def has_single_extension(filename):
    """
    Checks if the filename has only one extension.  Avoids double extensions like .tar.gz
    """
    return filename.count('.') == 1


def validate_file_content(file_path):
    """
    Validates file content using python-magic.
    """
    try:
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(file_path)

        # Check magic database age
        magic_db_path = mime.magic_file
        if magic_db_path and os.path.exists(magic_db_path):
            magic_db_age = (time.time() - os.path.getmtime(magic_db_path)) / (60 * 60 * 24)
            if magic_db_age > MAGIC_DB_MAX_AGE_DAYS:
                logging.warning(f"Magic database is older than {MAGIC_DB_MAX_AGE_DAYS} days. Consider updating it.")
        else:
            logging.warning("Could not determine age of magic database.")


        if mime_type.startswith('image/'):
            try:
                img = Image.open(file_path)
                width, height = img.size
                if width > MAX_IMAGE_WIDTH or height > MAX_IMAGE_HEIGHT:
                    logging.warning(f"Image dimensions exceed limits: {width}x{height}")
                    return False  # Limit image dimensions

                # Strip EXIF data
                try:
                    piexif.remove(file_path)
                    logging.info("EXIF data stripped from image.")
                except Exception as e:
                    logging.warning(f"Error stripping EXIF data: {e}")

                # Format Validation
                try:
                    img.verify()  # Verify that it's a valid image
                except Exception as e:
                    logging.error(f"Invalid image format: {e}")
                    return False

            except Exception as e:
                logging.error(f"Invalid image format or processing error: {e}")
                return False # Invalid image format

        elif mime_type == 'text/plain':
            # Further text-specific validation (e.g., encoding, character set)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if len(line) > 1000:  # Example line length limit
                            logging.warning("Line length exceeds limit.")
                            return False
                    f.seek(0) # Reset file pointer to the beginning
                    f.read() # Check if file is valid UTF-8
            except UnicodeDecodeError:
                logging.warning("Invalid UTF-8 encoding.")
                return False
        elif mime_type == 'application/pdf':
            # Further PDF-specific validation (e.g., PDF structure)
            try:
                with open(file_path, 'rb') as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    num_pages = len(pdf_reader.pages)
                    if num_pages > 100: # Example page limit
                        logging.warning("PDF exceeds maximum page limit.")
                        return False

                    # Detect embedded JavaScript (basic check)
                    for page in pdf_reader.pages:
                        if "/JavaScript" in str(page.get_contents()):
                            logging.warning("PDF contains embedded JavaScript.")
                            return False

            except Exception as e:
                logging.error(f"Invalid PDF format or processing error: {e}")
                return False
        else:
            logging.warning(f"Disallowed MIME type: {mime_type}")
            return False  # Unknown or disallowed MIME type

        return True
    except Exception as e:
        logging.error(f"Content validation error: {e}")
        return False


def execute_in_sandbox(file_path):
    """
    Executes the uploaded file in a sandboxed environment.

    **CRITICAL SECURITY WARNING:** Chroot jails are **NOT** a reliable security
    solution and can be bypassed by a determined attacker. **DO NOT USE CHROOT
    IN PRODUCTION** where security is paramount. Consider using more robust
    sandboxing techniques like Docker or VMs.

    **Docker/Containerization Recommendation:** Docker provides a more isolated and
    controlled environment with resource limits, network isolation, and a more
    robust security model. Use a minimal base image and drop privileges within
    the container. For example, create a Dockerfile that starts from a
    `alpine` base image, adds the necessary dependencies, and runs the script
    as a non-root user.

    **Virtual Machines (VMs):** For the highest level of isolation, consider using
    VMs. VMs provide hardware-level isolation, making escapes significantly more
    difficult. However, they come with higher resource overhead.

    **Sandboxing Libraries (Restricted Python Execution):** If the goal is to
    execute Python code, explore sandboxing libraries like `restrictedpython` or
    `pypy-sandbox`. These libraries allow you to define a restricted execution
    environment within the Python interpreter itself. This is generally safer
    than relying on chroot.

    This function assumes you have a basic chroot environment set up.  See below
    for instructions on creating one.
    """
    CHROOT_PATH = '/opt/sandbox'  # Path to the chroot jail

    # Create a unique directory within the chroot for this execution
    execution_dir = os.path.join(CHROOT_PATH, 'tmp', str(uuid.uuid4()))
    os.makedirs(execution_dir, exist_ok=True)

    # Copy the file into the chroot environment
    chroot_file_path = os.path.join(execution_dir, os.path.basename(file_path))
    shutil.copy2(file_path, chroot_file_path)  # Copy with metadata

    # Make the file executable (if necessary)
    os.chmod(chroot_file_path, 0o755)

    try:
        # Execute the file within the chroot jail using subprocess
        # The `chroot` command changes the root directory for the process.
        command = ['chroot', CHROOT_PATH, 'bash', '-c', f'cd /tmp/{os.path.basename(execution_dir)}; ./"{os.path.basename(file_path)}"']
        process = subprocess.Popen(command,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   cwd='/',  # Important: Set cwd to / within the chroot
                                   )
        stdout, stderr = process.communicate(timeout=60)  # Timeout after 60 seconds

        logging.info(f"Stdout: {stdout.decode()}")
        logging.info(f"Stderr: {stderr.decode()}")

        if process.returncode != 0:
            logging.error(f"Execution failed with return code: {process.returncode}")
            return False

        return True

    except subprocess.TimeoutExpired:
        logging.error("Execution timed out.")
        process.kill()
        return False
    except Exception as e:
        logging.error(f"Error executing in sandbox: {e}")
        return False
    finally:
        # Clean up the execution directory within the chroot
        try:
            shutil.rmtree(execution_dir)
        except OSError as e:
            logging.error(f"Error cleaning up execution directory: {e}")


@app.route('/upload', methods=['POST'])
@limiter.limit("5/minute")  # Example: Limit uploads to 5 per minute
def upload_file():
    """
    Handles file uploads with security measures.
    """
    if 'file' not in request.files:
        abort(400, 'No file part')

    file = request.files['file']

    if file.filename == '':
        abort(400, 'No selected file')

    if file and allowed_file(file.filename) and has_single_extension(file.filename):
        # 1. Assign a unique filename
        filename = secure_filename(file.filename)  # Sanitize filename

        if len(filename) > MAX_FILENAME_LENGTH:
            abort(400, f"Filename exceeds maximum length of {MAX_FILENAME_LENGTH} characters")

        unique_filename = str(uuid.uuid4()) + "_" + filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        # Ensure the path is within the upload folder (Path Traversal Prevention)
        if not os.path.abspath(file_path).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
            logging.error("Attempted path traversal.")
            abort(400, "Invalid file path")


        # 2. Save the file
        file.save(file_path)

        # 3. Validate file content and metadata
        if not validate_file_content(file_path):
            os.remove(file_path)
            abort(400, 'Invalid file content')

        # 4. Execute in a sandbox (if applicable and if the file is meant to be executed)
        #    This example assumes that only files with a specific extension (e.g., .sh, .py)
        #    should be executed.  Adjust the logic as needed.
        if filename.endswith(('.sh', '.py')):  # Example: Execute shell scripts or Python scripts
            if execute_in_sandbox(file_path):
                return 'File uploaded and executed successfully in sandbox', 200, {'Content-Type': 'text/plain'}
            else:
                os.remove(file_path)
                abort(500, 'File execution failed in sandbox')
        else:
            return 'File uploaded successfully (not executed)', 200, {'Content-Type': 'text/plain'}

    else:
        abort(400, 'Invalid file type or filename')


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """
    Serves uploaded files (with security considerations).
    """
    # Sanitize the filename to prevent path traversal
    safe_filename = secure_filename(filename)
    if safe_filename != filename:
        abort(400, "Invalid filename")

    # Ensure the path is within the upload folder (Path Traversal Prevention)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    if not os.path.abspath(file_path).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        logging.error("Attempted path traversal.")
        abort(400, "Invalid file path")

    return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename)


@app.errorhandler(400)
def bad_request(error):
    logging.warning(f"Bad Request: {error.description}")
    return f"Bad Request: {error.description}", 400, {'Content-Type': 'text/plain'}


@app.errorhandler(500)
def internal_server_error(error):
    logging.error(f"Internal Server Error: {error.description}")
    return f"Internal Server Error: {error.description}", 500, {'Content-Type': 'text/plain'}


if __name__ == '__main__':
    import time
    app.run(debug=True)

