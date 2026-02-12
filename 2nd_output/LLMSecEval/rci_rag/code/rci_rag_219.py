import os
import uuid
import mimetypes
from flask import Flask, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
import subprocess
import shutil
import pwd
import grp
import resource  # For resource limits
import logging
import tempfile  # For secure temporary file handling
import magic  # For more accurate MIME type detection

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Whitelist extensions
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit
SANDBOX_BASE_DIR = 'sandbox'
USER_NAME = 'sandbox_user'  # Dedicated user for execution
GROUP_NAME = 'sandbox_group' # Dedicated group for execution
CHROOT_BASE_DIR = '/opt/chroot' # Base directory for chroot environments

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
        return None

def get_group_id(groupname):
    """Gets the group ID (GID) for a given groupname."""
    try:
        return grp.getgrnam(groupname).gr_gid
    except KeyError:
        return None


def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS and filename.count('.') == 1


def validate_file_content(filepath):
    """Validates the file content based on its type."""
    try:
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(filepath)

        if mime_type is None:
            return False, "Unknown file type."

        if mime_type.startswith('image/'):
            try:
                from PIL import Image
                img = Image.open(filepath)
                img.verify()  # Verify image integrity
                # Optionally, resave the image to sanitize it
                # img.save(filepath)
            except Exception as e:
                return False, f"Invalid image: {str(e)}"
        elif mime_type == 'text/plain':
            with open(filepath, 'r') as f:
                for line in f:
                    if len(line) > 4096:
                        return False, "Line too long in text file."
        elif mime_type == 'application/pdf':
            try:
                import pikepdf
                try:
                    pikepdf.Pdf.open(filepath)
                except pikepdf._qpdf.PdfError as e:
                    return False, f"Invalid PDF: {e}"
            except ImportError:
                logging.warning("pikepdf not installed.  PDF validation will be skipped.")
                pass # Placeholder for PDF validation
        else:
            return False, "Unsupported file type."

        return True, "File content validated."

    except Exception as e:
        return False, f"Content validation error: {str(e)}"


def create_chroot(sandbox_dir):
    """Creates a minimal chroot environment."""
    # Create necessary directories inside the chroot
    os.makedirs(os.path.join(sandbox_dir, 'tmp'), exist_ok=True)
    os.makedirs(os.path.join(sandbox_dir, 'usr', 'bin'), exist_ok=True)
    os.makedirs(os.path.join(sandbox_dir, 'dev'), exist_ok=True)
    os.makedirs(os.path.join(sandbox_dir, 'proc'), exist_ok=True)
    os.makedirs(os.path.join(sandbox_dir, 'sys'), exist_ok=True)

    # Copy essential binaries (minimal set for python execution)
    shutil.copy2('/usr/bin/python3', os.path.join(sandbox_dir, 'usr', 'bin'))
    shutil.copy2('/lib64/ld-linux-x86-64.so.2', os.path.join(sandbox_dir)) # Copy dynamic linker
    # Copy necessary libraries (use ldd python3 to find dependencies)
    # Example:
    # ldd /usr/bin/python3
    #   linux-vdso.so.1 (0x00007ffc6b927000)
    #   libpthread.so.0 => /lib64/libpthread.so.0 (0x00007f2996599000)
    #   libdl.so.2 => /lib64/libdl.so.2 (0x00007f2996593000)
    #   libutil.so.1 => /lib64/libutil.so.1 (0x00007f299658e000)
    #   libm.so.6 => /lib64/libm.so.6 (0x00007f299644b000)
    #   libc.so.6 => /lib64/libc.so.6 (0x00007f299627f000)
    #   /lib64/ld-linux-x86-64.so.2 (0x00007f2996600000)
    try:
        shutil.copy2('/lib64/libpthread.so.0', os.path.join(sandbox_dir, 'lib64'))
        shutil.copy2('/lib64/libdl.so.2', os.path.join(sandbox_dir, 'lib64'))
        shutil.copy2('/lib64/libutil.so.1', os.path.join(sandbox_dir, 'lib64'))
        shutil.copy2('/lib64/libm.so.6', os.path.join(sandbox_dir, 'lib64'))
        shutil.copy2('/lib64/libc.so.6', os.path.join(sandbox_dir, 'lib64'))
    except FileNotFoundError as e:
        logging.warning(f"Library not found during chroot creation: {e}.  Chroot may not function correctly.")

    # Create device nodes (essential for some programs)
    try:
        subprocess.run(['mount', '-o', 'bind,ro', '/dev', os.path.join(sandbox_dir, 'dev')], check=False)
        subprocess.run(['mount', '-o', 'bind,ro', '/proc', os.path.join(sandbox_dir, 'proc')], check=False)
        subprocess.run(['mount', '-o', 'bind,ro', '/sys', os.path.join(sandbox_dir, 'sys')], check=False)
    except subprocess.CalledProcessError as e:
        logging.warning(f"Failed to mount /dev, /proc, or /sys in chroot: {e}.  Chroot may not function correctly.")


def execute_in_sandbox(filepath):
    """Executes the file in a sandboxed environment using chroot and a dedicated user."""

    sandbox_id = str(uuid.uuid4())
    chroot_dir = os.path.join(CHROOT_BASE_DIR, sandbox_id) # Unique chroot directory

    os.makedirs(chroot_dir, exist_ok=True)

    # Create the chroot environment
    create_chroot(chroot_dir)

    # Create a temporary directory inside the chroot for the sandbox
    chroot_sandbox_dir = os.path.join(chroot_dir, 'sandbox')
    os.makedirs(chroot_sandbox_dir, exist_ok=True)

    # Create a temporary file inside the chroot sandbox
    try:
        # Copy the file into the chroot sandbox
        sandbox_filepath = os.path.join(chroot_sandbox_dir, os.path.basename(filepath))
        shutil.copy2(filepath, sandbox_filepath)  # Copy with metadata

        # Change ownership of the chroot directory and the file to the sandbox user
        user_id = get_user_id(USER_NAME)
        group_id = get_group_id(GROUP_NAME)

        if user_id is None or group_id is None:
            return "Error: Sandbox user or group not found.", 500

        os.chown(chroot_sandbox_dir, user_id, group_id)
        os.chown(sandbox_filepath, user_id, group_id)

        # Make the sandbox directory read-only for the sandbox user (except for /tmp)
        # This is a simplified example; a more robust solution would use capabilities.
        subprocess.run(['chmod', '500', chroot_sandbox_dir], check=True) # r-x for owner, --- for others
        subprocess.run(['chmod', '777', os.path.join(chroot_dir, 'tmp')], check=True) # Full access to /tmp

        # Construct the command to execute within the chroot
        command = ['chroot', chroot_dir, '/usr/bin/python3', f'/sandbox/{os.path.basename(filepath)}']  # Execute Python script directly

        # Set resource limits
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (10, 10))  # 10 seconds CPU time limit
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))  # 256MB memory limit
            resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024)) # 10MB file size limit
            resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024)) # Limit open file descriptors
            resource.setrlimit(resource.RLIMIT_NPROC, (100, 100)) # Limit number of processes
        except Exception as e:
            logging.warning(f"Failed to set resource limits: {e}")

        # Execute the command as the sandboxed user
        import os

        def demote(user_uid, user_gid):
            def set_ids():
                os.setgid(user_gid)
                os.setuid(user_uid)
            return set_ids

        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd='/',  # Set working directory inside the chroot
            preexec_fn=demote(user_id, group_id)
        )

        stdout, stderr = process.communicate(timeout=10)  # Timeout after 10 seconds

        if process.returncode != 0:
            return f"Execution failed with error: {stderr.decode()}", 500

        return f"Execution successful. Output: {stdout.decode()}", 200

    except subprocess.TimeoutExpired:
        process.kill()
        return "Execution timed out.", 500
    except Exception as e:
        return f"Sandbox execution error: {str(e)}", 500
    finally:
        # Clean up the chroot directory
        try:
            # Unmount /dev, /proc, and /sys
            try:
                subprocess.run(['umount', os.path.join(chroot_dir, 'dev')], check=False)
                subprocess.run(['umount', os.path.join(chroot_dir, 'proc')], check=False)
                subprocess.run(['umount', os.path.join(chroot_dir, 'sys')], check=False)
            except subprocess.CalledProcessError as e:
                logging.warning(f"Failed to unmount /dev, /proc, or /sys: {e}")

            shutil.rmtree(chroot_dir)
        except Exception as e:
            logging.error(f"Error cleaning up chroot: {str(e)}")


@app.route('/', methods=['GET', 'POST'])
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
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Use a temporary file
            with tempfile.NamedTemporaryFile(delete=False, dir=app.config['UPLOAD_FOLDER']) as tmp_file:
                try:
                    file.save(tmp_file.name)
                    filepath = tmp_file.name

                    # Validate file content
                    is_valid, validation_message = validate_file_content(filepath)
                    if not is_valid:
                        os.remove(filepath)  # Remove invalid file
                        return f"File validation failed: {validation_message}", 400

                    # Execute in sandbox
                    result, status_code = execute_in_sandbox(filepath)
                    return result, status_code
                finally:
                    os.remove(filepath)  # Ensure file is always removed
        else:
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
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)


if __name__ == "__main__":
    create_sandbox_user()  # Create the sandbox user on startup
    app.run(debug=True)

