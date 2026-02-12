import os
import logging
import time
import os.path

# Configure logging (optional, but recommended for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def delete_image(path, max_retries=3, retry_delay=0.1, allowed_extensions=None, user_id=None):  # Added user_id
    """
    Delete the image from the given path in the current directory if it exists.

    Security Considerations:
    - Path traversal prevention: Checks for ".." in the path.
    - File extension allowlist: Only allows deletion of specific image types.
    - File existence check: Verifies the file exists before attempting deletion.
    - Logging: Logs the deletion attempt for auditing.
    - Retry mechanism: Attempts to delete the file multiple times in case of race conditions.
    - Symbolic link handling: Prevents deletion of symbolic links.

    :param path: The path of the image to be deleted.
    :param max_retries: The maximum number of times to retry the deletion.
    :param retry_delay: The delay (in seconds) between retries.
    :param allowed_extensions: A list of allowed file extensions.  If None, defaults to ['.jpg', '.jpeg', '.png', '.gif']
    :param user_id: (Optional) The ID of the user initiating the deletion.  For auditing.
    :return: None
    """

    if allowed_extensions is None:
        allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif']

    # 1. Input Validation and Sanitization (Path Traversal Prevention)
    absolute_path = os.path.abspath(path)
    normalized_path = os.path.normpath(absolute_path)

    # Ensure the path stays within the current working directory (or a more specific allowed directory)
    safe_directory = os.getcwd()  # Or a more specific allowed directory
    if not normalized_path.startswith(safe_directory + os.sep):
        logging.warning(f"Attempted path traversal detected: {path} (User: {user_id})") # Added user_id to log
        print("Invalid path: Path traversal detected.")
        return


    # 2. Input Validation and Sanitization (File Extension Allowlist)
    file_extension = os.path.splitext(path)[1].lower()
    if file_extension not in allowed_extensions:
        logging.warning(f"Attempted deletion of file with disallowed extension: {path} (User: {user_id})") # Added user_id to log
        print("Invalid file type: Only image files are allowed.")
        return


    # 4. Check for Symbolic Links
    if os.path.islink(absolute_path):
        logging.warning(f"Attempted deletion of symbolic link: {path} (User: {user_id})") # Added user_id to log
        print("Cannot delete symbolic links directly.")
        return

    # 5. Check if the file exists before attempting to delete it
    if not os.path.exists(absolute_path):
        logging.warning(f"Attempted deletion of non-existent file: {absolute_path} (User: {user_id})") # Added user_id to log
        print("File not found.")
        return

    # 6.  Check if the file is a file (not a directory or other special file)
    if not os.path.isfile(absolute_path):
        logging.warning(f"Attempted deletion of non-file object: {absolute_path} (User: {user_id})") # Added user_id to log
        print("Not a file.")
        return

    # 7. Check Permissions
    if not os.access(absolute_path, os.W_OK):
        logging.warning(f"Insufficient permissions to delete file: {absolute_path} (User: {user_id})") # Added user_id to log
        print("Insufficient permissions to delete file.")
        return

    try:
        for attempt in range(max_retries):
            try:
                os.remove(absolute_path)
                logging.info(f"Successfully deleted file: {absolute_path} (attempt {attempt+1}, User: {user_id})") # Added user_id to log
                print("File deleted successfully.")
                return  # Success!
            except OSError as e:
                if isinstance(e, FileNotFoundError):
                    if attempt < max_retries - 1:
                        logging.warning(f"File not found during deletion, retrying in {retry_delay} seconds... (User: {user_id})") # Added user_id to log
                        time.sleep(retry_delay)
                    else:
                        logging.error(f"File not found after multiple retries: {absolute_path} (User: {user_id})") # Added user_id to log
                        print("Error: File not found after multiple retries.")
                        return
                else:
                    logging.error(f"Error deleting file {absolute_path}: {e} (User: {user_id})") # Added user_id to log
                    print("Error deleting file: Please check the logs for details.")
                    return
            except PermissionError as e:
                logging.error(f"Permission error deleting file {absolute_path}: {e} (User: {user_id})") # Added user_id to log
                print("Insufficient permissions to delete the file.")
                return

    except Exception as e: # Catch any other exceptions
        logging.error(f"Unexpected error during deletion: {e} (User: {user_id})") # Added user_id to log
        print(f"Unexpected error during deletion: {e}")
        return

# Example Usage (for testing - REMOVE in production if not needed)
if __name__ == '__main__':
    # Create a dummy image file for testing
    test_file = "test_image.png"
    with open(test_file, "w") as f:
        f.write("This is a test image file.")

    # Create a symbolic link for testing
    try:
        os.symlink(test_file, "test_image_link.png")
    except OSError as e:
        print(f"Could not create symbolic link (may require admin privileges): {e}")

    # Test cases
    delete_image(test_file, user_id="test_user")  # Should delete the file
    delete_image("nonexistent_file.jpg", user_id="test_user")  # Should print "File not found."
    delete_image("../sensitive_data.txt", user_id="test_user")  # Should print "Invalid path: Path traversal detected."
    delete_image("test_image.exe", user_id="test_user") # Should print "Invalid file type: Only image files are allowed."
    delete_image("test_image_link.png", user_id="test_user") # Should print "Cannot delete symbolic links directly."

    # Clean up (remove the test file if it wasn't deleted)
    if os.path.exists(test_file):
        os.remove(test_file)
    if os.path.exists("test_image_link.png"):
        os.remove("test_image_link.png")

