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
USER_NAME = 'sandbox_user'  # Dedicated user for execution
USER_ID = 1001  # Replace with a suitable user ID
GROUP_ID = 1001  # Replace with a suitable group ID

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure upload and sandbox directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SANDBOX_BASE_DIR, exist_ok=True)


def create_sandbox(filename):
    """Creates a chroot jail for executing the uploaded file."""
    sandbox_id = str(uuid.uuid4())
    sandbox_path = os.path.join(SANDBOX_BASE_DIR, sandbox_id)
    os.makedirs(sandbox_path, exist_ok=True)

    # Copy the uploaded file into the sandbox
    src_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    dest_file = os.path.join(sandbox_path, filename)
    shutil.copy2(src_file, dest_file)  # Copy with metadata

    # Set permissions:  Make the file executable only by the sandbox user
    os.chmod(dest_file, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    # Create necessary directories inside the sandbox (e.g., /tmp)
    os.makedirs(os.path.join(sandbox_path, 'tmp'), exist_ok=True)

    return sandbox_path, dest_file


def execute_in_sandbox(sandbox_path, filename):
    """Executes the file within the chroot jail as a limited user."""
    try:
        # Use subprocess.run with appropriate security measures
        command = [
            'chroot',
            sandbox_path,
            'su',  # Switch user
            USER_NAME,
            '-c',  # Execute command
            f'./{filename}'  # Execute the file
        ]

        result = subprocess.run(command,
                                capture_output=True,
                                text=True,
                                timeout=10,  # Timeout after 10 seconds
                                check=False)  # Don't raise exception on non-zero exit code

        return result.stdout, result.stderr, result.returncode

    except subprocess.TimeoutExpired:
        return "", "Execution timed out", 1


def cleanup_sandbox(sandbox_path):
    """Removes the sandbox directory."""
    try:
        shutil.rmtree(sandbox_path)
    except OSError as e:
        print(f"Error cleaning up sandbox: {e}")


def allowed_file(filename):
    """Checks if the file extension is allowed and has only one extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS and \
           filename.count('.') == 1


def validate_file_content(filename):
    """Validates the file content based on its MIME type."""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    mime_type, _ = mimetypes.guess_type(filepath)

    if mime_type is None:
        return False, "Could not determine MIME type."

    if mime_type.startswith('image/'):
        # Basic image validation (can be improved with libraries like Pillow)
        try:
            from PIL import Image
            img = Image.open(filepath)
            img.verify()  # Verify image integrity
            return True, None
        except Exception as e:
            return False, f"Invalid image file: {e}"

    elif mime_type == 'text/plain':
        # Basic text file validation (e.g., check for excessive length)
        with open(filepath, 'r') as f:
            content = f.read()
            if len(content) > 10240:  # Limit to 10KB
                return False, "Text file too large."
        return True, None

    elif mime_type == 'application/pdf':
        # Add PDF validation logic here (using a library like PyPDF2)
        # This is a placeholder - PDF validation is complex.
        return True, None  # Placeholder - Implement proper PDF validation

    else:
        return False, "Unsupported file type."


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return render_template('upload.html', error='No file part')
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return render_template('upload.html', error='No selected file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = str(uuid.uuid4()) + "_" + filename  # Unique filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)

            # Validate file content
            is_valid, validation_error = validate_file_content(unique_filename)
            if not is_valid:
                os.remove(filepath)  # Remove invalid file
                return render_template('upload.html', error=f"File validation failed: {validation_error}")

            # Create and execute in sandbox
            sandbox_path, sandbox_file = create_sandbox(unique_filename)
            stdout, stderr, returncode = execute_in_sandbox(sandbox_path, unique_filename)
            cleanup_sandbox(sandbox_path)

            return render_template('result.html', filename=unique_filename, stdout=stdout, stderr=stderr, returncode=returncode)
        else:
            return render_template('upload.html', error='Invalid file type or multiple extensions.')
    return render_template('upload.html')


@app.route('/uploads/<name>')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)


@app.route('/result')
def result():
    return render_template('result.html')


if __name__ == "__main__":
    # Create a dedicated user for running the uploaded files
    try:
        subprocess.run(['useradd', '-r', '-u', str(USER_ID), '-g', str(GROUP_ID), '-d', '/nonexistent', '-s', '/usr/sbin/nologin', USER_NAME], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        if "already exists" not in e.stderr:
            print(f"Error creating user: {e.stderr}")

    app.run(debug=True, host="0.0.0.0", port=5000)

