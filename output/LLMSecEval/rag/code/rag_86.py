import os
import uuid
import mimetypes
import subprocess
import shutil
import stat
from flask import Flask, request, redirect, url_for, send_from_directory, render_template
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}  # Whitelist extensions
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit
SANDBOX_BASE_DIR = 'sandbox'
USER_ID = 1001  # Example user ID for the isolated account
GROUP_ID = 1001 # Example group ID for the isolated account

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure upload and sandbox directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SANDBOX_BASE_DIR, exist_ok=True)


def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def create_isolated_user():
    """Creates an isolated user account (Linux specific).  Requires root privileges."""
    try:
        # Check if the user already exists
        subprocess.run(['id', '-u', str(USER_ID)], check=True, capture_output=True)
        print(f"User with UID {USER_ID} already exists.")
    except subprocess.CalledProcessError:
        # User does not exist, create it
        try:
            subprocess.run(['groupadd', '-g', str(GROUP_ID), 'sandbox_group'], check=True, capture_output=True)
            subprocess.run(['useradd', '-u', str(USER_ID), '-g', 'sandbox_group', '-m', '-d', '/home/sandbox_user', 'sandbox_user'], check=True, capture_output=True)
            subprocess.run(['passwd', '-d', 'sandbox_user'], check=True, capture_output=True) # Remove password for security
            print(f"User 'sandbox_user' (UID: {USER_ID}, GID: {GROUP_ID}) created.")
        except subprocess.CalledProcessError as e:
            print(f"Error creating user: {e.stderr.decode()}")
            return False
    return True


def create_sandbox(filename):
    """Creates a chroot jail for executing the uploaded file."""
    sandbox_id = str(uuid.uuid4())
    sandbox_path = os.path.join(SANDBOX_BASE_DIR, sandbox_id)
    os.makedirs(sandbox_path, exist_ok=True)

    # Copy necessary files and directories into the sandbox
    # This is a MINIMAL example.  You'll need to copy more dependencies
    # depending on what the uploaded file needs to execute.  Be VERY careful
    # about what you copy in.  Less is better.
    try:
        # Create a directory for the user's home directory inside the sandbox
        user_home_path = os.path.join(sandbox_path, "home", "sandbox_user")
        os.makedirs(user_home_path, exist_ok=True)

        # Copy the uploaded file into the sandbox user's home directory
        shutil.copy(os.path.join(UPLOAD_FOLDER, filename), user_home_path)
        sandbox_file_path = os.path.join(user_home_path, filename)

        # Set ownership and permissions within the sandbox
        os.chown(sandbox_path, USER_ID, GROUP_ID)
        os.chown(user_home_path, USER_ID, GROUP_ID)
        os.chown(sandbox_file_path, USER_ID, GROUP_ID)
        os.chmod(sandbox_file_path, 0o700)  # Make executable by owner only

    except Exception as e:
        print(f"Error creating sandbox: {e}")
        shutil.rmtree(sandbox_path, ignore_errors=True)
        return None, None

    return sandbox_path, sandbox_file_path


def execute_in_sandbox(sandbox_path, sandbox_file_path):
    """Executes the uploaded file within the chroot jail."""
    try:
        # Use subprocess to execute the file within the chroot jail as the isolated user
        # The `chroot` command changes the root directory for the current process and its children.
        # The `su` command switches the user ID.
        command = [
            'chroot', sandbox_path,
            'su', 'sandbox_user',
            '-c', f'/home/sandbox_user/{os.path.basename(sandbox_file_path)}'
        ]

        result = subprocess.run(command, capture_output=True, text=True, timeout=10) # Add timeout
        print(f"Sandbox execution result: {result}")

        if result.returncode != 0:
            print(f"Error executing in sandbox: {result.stderr}")
            return f"Execution failed with error: {result.stderr}"
        else:
            return result.stdout

    except subprocess.TimeoutExpired:
        return "Execution timed out."
    except Exception as e:
        print(f"Error executing in sandbox: {e}")
        return f"Execution failed: {e}"
    finally:
        # Clean up the sandbox after execution
        shutil.rmtree(sandbox_path, ignore_errors=True)


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return render_template('upload.html', message='No file part')
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return render_template('upload.html', message='No selected file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Ensure only one extension
            if filename.count('.') > 1:
                return render_template('upload.html', message='Invalid filename: Multiple extensions')

            # Assign a unique filename
            unique_filename = str(uuid.uuid4()) + "_" + filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)

            # Validate content and metadata (basic example)
            mime_type = mimetypes.guess_type(file_path)[0]
            if mime_type not in ['image/png', 'image/jpeg', 'application/pdf', 'text/plain']:
                os.remove(file_path)  # Remove invalid file
                return render_template('upload.html', message='Invalid file type')

            # Create sandbox and execute
            sandbox_path, sandbox_file_path = create_sandbox(unique_filename)
            if sandbox_path and sandbox_file_path:
                execution_result = execute_in_sandbox(sandbox_path, sandbox_file_path)
                return render_template('upload.html', message=f'File uploaded and executed. Result: {execution_result}')
            else:
                return render_template('upload.html', message='Failed to create sandbox.')

        else:
            return render_template('upload.html', message='Invalid file type. Allowed types: ' + ', '.join(ALLOWED_EXTENSIONS))
    return render_template('upload.html', message='')


@app.route('/uploads/<name>')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Warning: This application requires root privileges to create isolated user accounts and chroot jails.")
        print("Please run this script with sudo.")

    if not create_isolated_user():
        print("Failed to create isolated user.  Exiting.")
    else:
        app.run(debug=True)

