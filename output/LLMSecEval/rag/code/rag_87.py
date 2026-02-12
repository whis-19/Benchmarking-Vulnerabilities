import os
import uuid
import mimetypes
import subprocess
import shutil
import stat
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Example allowed extensions
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def create_sandbox(sandbox_path):
    """Creates a chroot jail sandbox."""
    try:
        os.makedirs(sandbox_path, exist_ok=True)

        # Create necessary directories inside the sandbox (e.g., /tmp)
        os.makedirs(os.path.join(sandbox_path, 'tmp'), exist_ok=True)

        # Create a minimal /dev directory (essential for some programs)
        dev_path = os.path.join(sandbox_path, 'dev')
        os.makedirs(dev_path, exist_ok=True)
        # Create null and urandom devices (common requirements)
        os.mknod(os.path.join(dev_path, 'null'), stat.S_IFCHR, os.makedev(1, 3))
        os.mknod(os.path.join(dev_path, 'urandom'), stat.S_IFCHR, os.makedev(1, 9))

        # Mount /proc (read-only) - be very careful with this!  Consider alternatives.
        # subprocess.run(['mount', '-t', 'proc', 'proc', os.path.join(sandbox_path, 'proc')], check=True)

        logging.info(f"Sandbox created at: {sandbox_path}")
    except Exception as e:
        logging.error(f"Error creating sandbox: {e}")
        raise

def remove_sandbox(sandbox_path):
    """Removes the chroot jail sandbox."""
    try:
        # Unmount /proc if it was mounted
        # subprocess.run(['umount', os.path.join(sandbox_path, 'proc')], check=False) # Ignore errors if not mounted

        shutil.rmtree(sandbox_path)
        logging.info(f"Sandbox removed from: {sandbox_path}")
    except Exception as e:
        logging.error(f"Error removing sandbox: {e}")
        raise

def is_safe_filename(filename):
    """
    Checks if a filename is safe.  This is a basic check and can be improved.
    """
    if not filename:
        return False
    if ".." in filename:
        return False
    if filename.startswith("/"):
        return False
    if filename.startswith("\\"):
        return False
    return True

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def has_single_extension(filename):
    """Checks if the filename has only one extension."""
    return filename.count('.') == 1

def validate_file_content(file_path, expected_mime_types):
    """Validates the file content based on expected MIME types."""
    try:
        mime_type = mimetypes.guess_type(file_path)[0]
        if mime_type not in expected_mime_types:
            logging.warning(f"File {file_path} has unexpected MIME type: {mime_type}")
            return False
        return True
    except Exception as e:
        logging.error(f"Error validating file content: {e}")
        return False

def upload_file(file_storage):
    """Handles the upload of a file securely."""
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    filename = file_storage.filename
    if not filename:
        logging.warning("No filename provided.")
        return "No filename provided", 400

    if not is_safe_filename(filename):
        logging.warning(f"Unsafe filename: {filename}")
        return "Unsafe filename", 400

    if not allowed_file(filename):
        logging.warning(f"File extension not allowed: {filename}")
        return "File extension not allowed", 400

    if not has_single_extension(filename):
        logging.warning(f"File has multiple extensions: {filename}")
        return "File has multiple extensions", 400

    # Generate a unique filename
    unique_filename = str(uuid.uuid4()) + "_" + filename
    file_path = os.path.join(UPLOAD_FOLDER, unique_filename)

    try:
        # Save the file
        file_storage.save(file_path)

        # Validate file size (after saving to avoid denial-of-service)
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            os.remove(file_path)  # Remove the file if it's too large
            logging.warning(f"File size exceeds maximum allowed: {file_size}")
            return "File size exceeds maximum allowed", 413

        # Validate file content (example: for images)
        if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            expected_mime_types = {'image/png', 'image/jpeg', 'image/gif'}
            if not validate_file_content(file_path, expected_mime_types):
                os.remove(file_path)
                return "Invalid file content", 400

        logging.info(f"File uploaded successfully to: {file_path}")
        return unique_filename, 200  # Return the unique filename

    except Exception as e:
        logging.error(f"Error uploading file: {e}")
        return "Error uploading file", 500

def execute_file_in_sandbox(filename):
    """Executes the uploaded file in a sandbox environment."""
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    sandbox_path = os.path.join(UPLOAD_FOLDER, "sandbox_" + filename)  # Unique sandbox per file

    try:
        create_sandbox(sandbox_path)

        # Copy the file into the sandbox
        sandbox_file_path = os.path.join(sandbox_path, filename)
        shutil.copy2(file_path, sandbox_file_path)  # copy2 preserves metadata

        # Make the file executable (if necessary) - be VERY careful with this!
        # Only do this if you absolutely trust the file type and have validated it.
        # os.chmod(sandbox_file_path, 0o755)

        # Execute the file within the chroot jail using subprocess
        # Use a non-root user account with limited privileges.  This example uses 'nobody'.
        command = ['chroot', sandbox_path, 'su', 'nobody', '-c', sandbox_file_path]  # Example
        # command = ['chroot', sandbox_path, sandbox_file_path] # If no specific user is needed

        process = subprocess.Popen(command,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   cwd='/',  # Set working directory inside the sandbox
                                   )

        stdout, stderr = process.communicate(timeout=60)  # Timeout after 60 seconds

        if process.returncode != 0:
            logging.error(f"File execution failed with code {process.returncode}: {stderr.decode()}")
            result = f"Execution failed: {stderr.decode()}"
        else:
            logging.info(f"File executed successfully: {stdout.decode()}")
            result = f"Execution output: {stdout.decode()}"

    except subprocess.TimeoutExpired:
        logging.error("File execution timed out.")
        process.kill()
        result = "Execution timed out"
    except Exception as e:
        logging.error(f"Error executing file in sandbox: {e}")
        result = f"Error: {e}"
    finally:
        remove_sandbox(sandbox_path)
        return result

# Example usage (replace with your actual file upload mechanism)
if __name__ == '__main__':
    # This is just a placeholder for how you'd get the file.  In a real web app,
    # you'd get the file from the request object (e.g., Flask's request.files).
    class MockFileStorage:
        def __init__(self, filename):
            self.filename = filename

        def save(self, destination):
            # Create a dummy file for testing
            with open(destination, 'w') as f:
                f.write("This is a test file.")

    # Simulate a file upload
    uploaded_file = MockFileStorage("test.txt")  # Replace with your actual file
    upload_result, status_code = upload_file(uploaded_file)

    if status_code == 200:
        print(f"File uploaded successfully. Unique filename: {upload_result}")
        execution_result = execute_file_in_sandbox(upload_result)
        print(f"Execution result: {execution_result}")
    else:
        print(f"File upload failed: {upload_result}")

