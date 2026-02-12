import os
import uuid
from flask import Flask, request, redirect, url_for
from werkzeug.utils import secure_filename
import subprocess
import magic  # For MIME type detection
from PIL import Image  # Requires Pillow library
import logging  # For logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}  # Whitelist extensions
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create the uploads directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    logging.info(f"Created upload directory: {UPLOAD_FOLDER}")


def allowed_file(filename):
    """
    Checks if the filename has an allowed extension and only one extension.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS and filename.count('.') == 1


def validate_file_content(file_path):
    """
    Validates the file content based on its MIME type.  Uses libmagic for robust type detection.
    """
    mime = magic.Magic(mime=True)
    try:
        mime_type = mime.from_file(file_path)
    except Exception as e:
        logging.error(f"Error determining MIME type for {file_path}: {e}")
        return False

    if mime_type == 'image/jpeg' or mime_type == 'image/png':
        # Basic image validation (can be extended with image library checks)
        try:
            img = Image.open(file_path)
            img.verify()  # Verify that it is actually an image

            # Re-encode the image to remove potential hidden data
            new_file_path = file_path + ".reencoded.png"  # Or .jpg, depending on original type
            img.save(new_file_path, "PNG", quality=85)  # Or "JPEG", control quality
            img.close()
            os.remove(file_path) # Remove the original
            os.rename(new_file_path, file_path) # Replace with re-encoded version
            logging.info(f"Image re-encoded and replaced: {file_path}")

        except Exception as e:
            logging.error(f"Image validation failed for {file_path}: {e}")
            return False
    elif mime_type == 'text/plain':
        # Basic text file validation (e.g., check for excessive length or unusual characters)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:  # Enforce UTF-8
                content = f.read()
                if len(content) > 10000:  # Limit text file size
                    logging.warning(f"Text file {file_path} exceeds maximum length.")
                    return False
                # Strip control characters
                content = ''.join(ch for ch in content if ch.isprintable())
                # Add more checks for malicious content if needed
                # Example: Check for HTML tags
                if "<" in content or ">" in content:
                    logging.warning(f"Possible HTML injection detected in {file_path}")
                    return False

                # Write the sanitized content back to the file (optional)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            logging.info(f"Text file {file_path} sanitized.")
        except Exception as e:
            logging.error(f"Text file validation error for {file_path}: {e}")
            return False

    elif mime_type == 'application/pdf':
        # PDF validation (can be extended with PDF library checks)
        # Note: PDF validation is complex and requires dedicated libraries.
        # This is a placeholder.  Consider using a library like PyPDF2 for more robust checks.
        try:
            import PyPDF2  # pip install PyPDF2
            with open(file_path, 'rb') as pdf_file:
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                # Check for JavaScript
                if '/JavaScript' in pdf_reader.trailer['/Root']:
                    logging.warning(f"JavaScript found in PDF {file_path}")
                    return False
                # Add more checks as needed (forms, actions, etc.)
        except ImportError:
            logging.error("PyPDF2 library not installed. PDF validation skipped.")
            return False # Or raise an exception if PDF validation is critical
        except Exception as e:
            logging.error(f"PDF validation failed for {file_path}: {e}")
            return False
    else:
        logging.warning(f"Unexpected MIME type: {mime_type} for {file_path}")
        return False

    return True


def execute_in_sandbox(file_path):
    """
    Executes the uploaded file in a sandboxed environment using a chroot jail and a limited user account.

    This is a simplified example and requires proper system configuration for a secure sandbox.
    """

    # 1. Create a dedicated user account (e.g., 'sandbox_user') with limited privileges.
    #    This should be done outside the application (e.g., using useradd).
    sandbox_user = 'sandbox_user'

    # 2. Create a chroot jail directory.
    chroot_dir = '/opt/sandbox'  # Example location.  MUST be properly configured.
    #    This directory should contain the necessary libraries and executables for the
    #    uploaded file to run.  It should be as minimal as possible.
    #    This setup is complex and requires careful planning.

    # 3. Construct the command to execute the file within the sandbox.
    command = [
        'chroot',
        chroot_dir,
        'su',  # Switch user
        '-s',  # Specify shell (important for security)
        '/bin/sh', # A very restricted shell
        sandbox_user,
        '-c',  # Execute command
        f'/app/{os.path.basename(file_path)}'  # Path to the file within the chroot jail
    ]

    try:
        # Get the UID of the sandbox user
        process = subprocess.Popen(['id', '-u', sandbox_user], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            logging.error(f"Failed to get UID for {sandbox_user}: {stderr.decode()}")
            return False
        sandbox_uid = int(stdout.decode().strip())

        # Execute the command with a timeout.
        result = subprocess.run(command, capture_output=True, text=True, timeout=10,
                                 preexec_fn=lambda: os.setuid(sandbox_uid)) # Replace 1001 with the actual UID of sandbox_user

        logging.info(f"Sandbox execution result (stdout): {result.stdout}")
        logging.info(f"Sandbox execution errors (stderr): {result.stderr}")

        if result.returncode != 0:
            logging.error(f"Sandbox execution failed with return code: {result.returncode}")
            return False

        return True

    except subprocess.TimeoutExpired:
        logging.error("Sandbox execution timed out.")
        return False
    except Exception as e:
        logging.error(f"Error executing in sandbox: {e}")
        return False


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            logging.warning("No file part in the request.")
            return 'No file part'
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            logging.warning("No file selected.")
            return 'No selected file'
        if file and allowed_file(file.filename):
            # Secure filename and unique name
            filename = secure_filename(file.filename)
            if filename != file.filename:
                logging.warning(f"Filename {file.filename} sanitized to {filename}")

            file_extension = filename.rsplit('.', 1)[1].lower()
            unique_filename = str(uuid.uuid4()) + '.' + file_extension
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            try:
                file.save(file_path)
                logging.info(f"File saved to: {file_path}")
            except Exception as e:
                logging.error(f"Error saving file: {e}")
                return "Error saving file"

            # Rename immediately after saving
            renamed_file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(uuid.uuid4())) # No extension
            try:
                os.rename(file_path, renamed_file_path)
                file_path = renamed_file_path
                logging.info(f"File renamed to: {file_path}")
            except Exception as e:
                logging.error(f"Error renaming file: {e}")
                os.remove(file_path) # Remove the file if renaming fails
                return "Error renaming file"


            # Validate file content
            if not validate_file_content(file_path):
                try:
                    os.remove(file_path)  # Remove invalid file
                    logging.info(f"Invalid file removed: {file_path}")
                except Exception as e:
                    logging.error(f"Error removing invalid file: {e}")
                return 'Invalid file content'

            # Execute in sandbox (if applicable and if the file is executable)
            if file_extension in {'txt', 'pdf'}: # Only execute specific types
                if not execute_in_sandbox(file_path):
                    try:
                        os.remove(file_path)
                        logging.info(f"Sandbox execution failed, file removed: {file_path}")
                    except Exception as e:
                        logging.error(f"Error removing file after sandbox failure: {e}")
                    return 'Execution in sandbox failed'

            return 'File uploaded successfully'
        else:
            logging.warning(f"Invalid file type or filename: {file.filename}")
            return 'Invalid file type or filename'
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


if __name__ == '__main__':
    app.run(debug=True)

