import os
import os.path
import logging

# Configure logging (optional, but recommended for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def delete_image(path):
    """
    Delete the image from the given path in the current directory if it exists.
    This function implements several security measures to prevent path traversal and other vulnerabilities.

    :param path: The path of the image to be deleted.
    :return: None
    """

    # 1. Input Validation and Sanitization:  Path Traversal Prevention
    if not isinstance(path, str):
        logging.error("Invalid path type.  Path must be a string.")
        return  # Or raise an exception if appropriate

    if ".." in path:
        logging.error("Path contains '..' which is a potential path traversal attempt.  Aborting.")
        return  # Or raise an exception

    # 2. Input Validation:  File Extension Allowlist (Example)
    allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif']  # Define allowed image extensions
    file_extension = os.path.splitext(path)[1].lower()
    if file_extension not in allowed_extensions:
        logging.error(f"File extension '{file_extension}' is not allowed.  Allowed extensions are: {allowed_extensions}")
        return  # Or raise an exception

    # 3.  Path Normalization (Important for security)
    # Convert the path to an absolute path and then normalize it.
    # This resolves symbolic links and removes redundant components like ".." and ".".
    absolute_path = os.path.abspath(path)
    normalized_path = os.path.normpath(absolute_path)

    # 4.  Check if the file exists BEFORE attempting to delete it.
    if not os.path.exists(normalized_path):
        logging.warning(f"File '{normalized_path}' does not exist.  No action taken.")
        return

    # 5.  Check if the path is a file (not a directory)
    if not os.path.isfile(normalized_path):
        logging.error(f"'{normalized_path}' is not a file.  Deletion aborted.")
        return

    # 6.  File Permissions Check (Optional, but recommended)
    # Check if the current user has write permissions to the file.
    if not os.access(normalized_path, os.W_OK):
        logging.error(f"Insufficient permissions to delete '{normalized_path}'.  Deletion aborted.")
        return

    # 7.  Secure File Deletion (Using a vetted library if possible)
    #  Consider using a library like 'shred' for more secure deletion, especially for sensitive data.
    #  However, 'shred' is not a standard Python library and might require external installation.
    #  For a basic secure deletion, we'll use os.remove.

    try:
        os.remove(normalized_path)
        logging.info(f"Successfully deleted file: '{normalized_path}'")
    except OSError as e:
        logging.error(f"Error deleting file '{normalized_path}': {e}")
        # Handle the error appropriately (e.g., retry, log, raise exception)


# Example Usage (for testing - REMOVE or COMMENT OUT in production)
if __name__ == '__main__':
    # Create a dummy file for testing
    test_file = "test_image.png"
    with open(test_file, "w") as f:
        f.write("This is a test file.")

    # Test cases:
    delete_image(test_file)  # Should delete the file
    delete_image("nonexistent_file.jpg")  # Should log a warning
    delete_image("../sensitive_data.txt")  # Should log an error (path traversal)
    delete_image("image.exe") # Should log an error (invalid extension)
    delete_image(123) # Should log an error (invalid type)

    # Create a directory to test directory deletion prevention
    os.makedirs("test_dir", exist_ok=True)
    delete_image("test_dir") # Should log an error (not a file)
    os.rmdir("test_dir") # Clean up the directory

