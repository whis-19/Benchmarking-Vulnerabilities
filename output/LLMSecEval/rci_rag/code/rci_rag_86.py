import os
import uuid
import mimetypes
from flask import Flask, request, redirect, url_for, send_from_directory, abort
from werkzeug.utils import secure_filename
import subprocess
import shutil
import pwd
import grp
import logging
import resource
import re
import magic  # For more reliable file type detection

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Whitelist extensions
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit
SANDBOX_BASE_DIR = 'sandbox'
USER_NAME = 'sandbox_user'  # Dedicated user for execution
GROUP_NAME = 'sandbox_group' # Dedicated group for execution
CHROOT_BASE_DIR = '/opt/chroot' # Base directory for chroot environments
MAX_FILENAME_LENGTH = 64  # Maximum filename length
MAX_FILE_SIZE_KB = 1024 # Maximum file size in KB
CPU_TIME_LIMIT = 5  # CPU time limit in seconds
MEMORY_LIMIT_MB = 64  # Memory limit in MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure upload and sandbox directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SANDBOX_BASE_DIR, exist_ok=True)
os.makedirs(CHROOT_BASE_DIR, exist_ok=True)


def create_sandbox_user():
    """Creates a dedicated user and group for sandboxed execution."""
    try:
        # Check if the user already exists
        pwd.getpwnam(USER_NAME)
        logging.info(f"User {USER_NAME} already exists.")
    except KeyError:
        try:
            # Create the group first
            subprocess.run(['groupadd', USER_NAME], check=True, capture_output=True)
            logging.info(f"Group {USER_NAME} created.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error creating group: {e.stderr.decode()}")
            raise

        try:
            # Create the user, adding them to the group
            subprocess.run(['useradd', '-m', '-g', USER_NAME, USER_NAME], check=True, capture_output=True)
            logging.info(f"User {USER_NAME} created.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error creating user: {e.stderr.decode()}")
            # Attempt to remove the group if user creation fails
            try:
                subprocess.run(['groupdel', USER_NAME], check=True, capture_output=True)
            except subprocess.CalledProcessError as e2:
                logging.error(f"Error deleting group after user creation failure: {e2.stderr.decode()}")
            raise

def get_user_id(username):
    """Gets the user ID (UID) for a given username."""
    try:
        return pwd.getpwnam(username).pw_uid
    except KeyError:
        logging.error(f"User {username} not found.")
        return None

def get_group_id(groupname):
    """Gets the group ID (GID) for a given groupname."""
    try:
        return grp.getgrnam(groupname).gr_gid
    except KeyError:
        logging.error(f"Group {groupname} not found.")
        return None


def allowed_file(filename):
    """Checks if the file extension is allowed."""
    if not filename:
        return False

    # Check filename length
    if len(filename) > MAX_FILENAME_LENGTH:
        logging.warning(f"Filename too long: {filename}")
        return False

    # Check for multiple extensions
    name, ext = os.path.splitext(filename)
    while ext:
        if ext[1:].lower() not in ALLOWED_EXTENSIONS:
            logging.warning(f"Invalid extension: {ext} in {filename}")
            return False
        name, ext = os.path.splitext(name)

    return True


def validate_file_content(filepath):
    """Validates the file content based on its type."""
    try:
        # Use python-magic for more reliable file type detection
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(filepath)

        if mime_type is None:
            logging.warning(f"Unknown file type for {filepath}")
            return False, "Unknown file type."

        if mime_type.startswith('image/'):
            try:
                from PIL import Image
                img = Image.open(filepath)
                img.verify()  # Verify image integrity
                img.close()
                logging.info(f"Image content validated for {filepath}")
                return True, "Image content validated."
            except Exception as e:
                logging.warning(f"Invalid image content for {filepath}: {str(e)}")
                return False, f"Invalid image content: {str(e)}"

        elif mime_type == 'text/plain':
            # Check for excessively long lines and potential shell commands
            with open(filepath, 'r') as f:
                for line in f:
                    if len(line) > 4096:  # Arbitrary limit
                        logging.warning(f"Line too long in text file {filepath}")
                        return False, "Line too long in text file."
                    if re.search(r'[;&|<>`$(){}]', line):  # Check for shell metacharacters
                        logging.warning(f"Potential shell command in text file {filepath}")
                        return False, "Potential shell command detected."

            logging.info(f"Text file content validated for {filepath}")
            return True, "Text file content validated."

        elif mime_type == 'application/pdf':
            try:
                import pdfminer.high_level
                # Attempt to extract text to validate PDF structure
                pdfminer.high_level.extract_text(filepath, maxpages=1)  # Limit to first page
                logging.info(f"PDF content validated for {filepath}")
                return True, "PDF content validated."
            except Exception as e:
                logging.warning(f"Invalid PDF content for {filepath}: {str(e)}")
                return False, f"Invalid PDF content: {str(e)}"

        else:
            logging.warning(f"Unsupported file type: {mime_type} for {filepath}")
            return False, "Unsupported file type."

    except Exception as e:
        logging.error(f"Content validation error for {filepath}: {str(e)}")
        return False, f"Content validation error: {str(e)}"


def create_chroot(sandbox_dir):
    """Creates a minimal chroot environment."""
    try:
        # Create necessary directories inside the chroot
        os.makedirs(os.path.join(sandbox_dir, 'tmp'), exist_ok=True)
        os.makedirs(os.path.join(sandbox_dir, 'usr', 'bin'), exist_ok=True)
        os.makedirs(os.path.join(sandbox_dir, 'lib'), exist_ok=True)
        os.makedirs(os.path.join(sandbox_dir, 'lib64'), exist_ok=True)  # For 64-bit systems
        os.makedirs(os.path.join(sandbox_dir, 'home', 'sandbox'), exist_ok=True) # Add home/sandbox

        # Copy essential binaries and libraries (minimal example)
        shutil.copy2('/usr/bin/python3', os.path.join(sandbox_dir, 'usr', 'bin'))
        # You'll need to identify and copy the necessary libraries for python3
        # using ldd /usr/bin/python3 and copying the listed libraries to the chroot
        # Example (replace with actual libraries from ldd):
        shutil.copy2('/lib/x86_64-linux-gnu/libc.so.6', os.path.join(sandbox_dir, 'lib'))
        shutil.copy2('/lib64/ld-linux-x86-64.so.2', os.path.join(sandbox_dir, 'lib64'))
        shutil.copy2('/lib/x86_64-linux-gnu/libpthread.so.0', os.path.join(sandbox_dir, 'lib'))
        shutil.copy2('/lib/x86_64-linux-gnu/libdl.so.2', os.path.join(sandbox_dir, 'lib'))
        shutil.copy2('/lib/x86_64-linux-gnu/libutil.so.1', os.path.join(sandbox_dir, 'lib'))
        shutil.copy2('/lib/x86_64-linux-gnu/libm.so.6', os.path.join(sandbox_dir, 'lib'))
        shutil.copy2('/usr/lib/x86_64-linux-gnu/libpython3.10.so.1.0', os.path.join(sandbox_dir, 'lib')) # Example python lib

        logging.info(f"Chroot environment created in {sandbox_dir}")
    except Exception as e:
        logging.error(f"Error creating chroot environment: {str(e)}")
        raise

def limit_resources():
    """Sets resource limits for the sandboxed process."""
    try:
        # CPU time limit (seconds)
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_TIME_LIMIT, CPU_TIME_LIMIT))

        # Memory limit (bytes)
        memory_limit_bytes = MEMORY_LIMIT_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))

        # File size limit (bytes) - prevent writing large files
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_SIZE_KB * 1024, MAX_FILE_SIZE_KB * 1024))

        logging.info("Resource limits set for the sandboxed process.")
    except Exception as e:
        logging.error(f"Error setting resource limits: {str(e)}")
        # Non-critical, continue execution


def execute_in_sandbox(filepath):
    """Executes the file in a sandboxed environment using chroot and a dedicated user."""

    sandbox_id = str(uuid.uuid4())
    sandbox_dir = os.path.join(SANDBOX_BASE_DIR, sandbox_id)  # Unique sandbox directory
    chroot_dir = os.path.join(CHROOT_BASE_DIR, sandbox_id) # Unique chroot directory
    os.makedirs(sandbox_dir, exist_ok=True)
    os.makedirs(chroot_dir, exist_ok=True)

    # Copy the file into the sandbox
    sandbox_filepath = os.path.join(sandbox_dir, os.path.basename(filepath))
    shutil.copy2(filepath, sandbox_filepath)  # Copy with metadata

    # Set up the chroot environment
    try:
        # Create the chroot environment
        create_chroot(chroot_dir)

        # Copy the sandbox directory into the chroot
        chroot_sandbox_dir = os.path.join(chroot_dir, 'home', 'sandbox')
        shutil.copytree(sandbox_dir, chroot_sandbox_dir)

        # Change ownership of the chroot directory and the file to the sandbox user
        user_id = get_user_id(USER_NAME)
        group_id = get_group_id(USER_NAME)

        if user_id is None or group_id is None:
            logging.error("Sandbox user or group not found.")
            return "Error: Sandbox user or group not found.", 500

        # Chown the chroot directory and its contents
        def chown_recursive(path, uid, gid):
            os.chown(path, uid, gid)
            for root, dirs, files in os.walk(path):
                for dir in dirs:
                    os.chown(os.path.join(root, dir), uid, gid)
                for file in files:
                    os.chown(os.path.join(root, file), uid, gid)

        chown_recursive(chroot_dir, user_id, group_id)

        # Make the sandbox directory read-only for the sandbox user (except for /tmp)
        # This is a simplified example; a more robust solution would use capabilities.
        subprocess.run(['chmod', '500', chroot_sandbox_dir], check=True) # r-x for owner, --- for others
        subprocess.run(['chmod', '777', os.path.join(chroot_sandbox_dir, 'tmp')], check=True) # Full access to /tmp

        # Construct the command to execute within the chroot
        command = ['chroot', chroot_dir, 'su', USER_NAME, '-c', '/usr/bin/python3 /home/sandbox/' + os.path.basename(sandbox_filepath)]  # Example: execute as Python script

        logging.info(f"Executing command: {' '.join(command)}")

        # Execute the command as the sandboxed user
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd='/',  # Set working directory inside the chroot
            preexec_fn=limit_resources  # Apply resource limits before execution
        )

        stdout, stderr = process.communicate(timeout=10)  # Timeout after 10 seconds

        if process.returncode != 0:
            logging.error(f"Execution failed with error: {stderr.decode()}")
            return f"Execution failed with error: {stderr.decode()}", 500

        logging.info(f"Execution successful. Output: {stdout.decode()}")
        return f"Execution successful. Output: {stdout.decode()}", 200

    except subprocess.TimeoutExpired:
        logging.error("Execution timed out.")
        process.kill()
        return "Execution timed out.", 500
    except Exception as e:
        logging.error(f"Sandbox execution error: {str(e)}")
        return f"Sandbox execution error: {str(e)}", 500
    finally:
        # Clean up the sandbox directory
        try:
            shutil.rmtree(sandbox_dir)
            shutil.rmtree(chroot_dir)
            logging.info(f"Sandbox and chroot directories cleaned up: {sandbox_dir}, {chroot_dir}")
        except Exception as e:
            logging.error(f"Error cleaning up sandbox: {str(e)}")


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request.")
            return 'No file part', 400
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No selected file.")
            return 'No selected file', 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = str(uuid.uuid4()) + "_" + filename  # Unique filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            try:
                file.save(filepath)
            except Exception as e:
                logging.error(f"Error saving file: {str(e)}")
                return "Error saving file.", 500

            # Validate file content
            is_valid, validation_message = validate_file_content(filepath)
            if not is_valid:
                logging.warning(f"File validation failed: {validation_message}")
                os.remove(filepath)  # Remove invalid file
                return f"File validation failed: {validation_message}", 400

            # Execute in sandbox
            result, status_code = execute_in_sandbox(filepath)
            os.remove(filepath)  # Remove file after execution (or failure)
            return result, status_code

        else:
            logging.warning("Invalid file type or extension.")
            return 'Invalid file type or extension.', 400
    return '''
    <!doctype html>
    <html>
    <head>
    <title>Upload new File</title>
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
    # Securely serve files, preventing path traversal
    try:
        return send_from_directory(app.config["UPLOAD_FOLDER"], secure_filename(name))
    except FileNotFoundError:
        abort(404)  # Or handle the error as appropriate


if __name__ == "__main__":
    create_sandbox_user()  # Create the sandbox user on startup
    app.run(debug=False) # Disable debug mode in production

