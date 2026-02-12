import os
import os.path
import logging

# Configure logging (optional, but recommended for debugging and auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def delete_image(path):
    """
    Delete the image from the given path in the current directory if it exists.

    :param path: The path of the image to be deleted.
    :return: None
    """

    # Input validation and sanitization:  Crucial for security.

    # 1. Check for path traversal attempts (e.g., ".." in the path).
    if ".." in path:
        logging.error("Path traversal detected: %s", path)
        print("Error: Invalid path. Path traversal detected.")  # Inform the user (optional)
        return  # Abort the operation

    # 2.  Check if the path is absolute.  If so, reject it or carefully control allowed directories.
    if os.path.isabs(path):
        logging.error("Absolute path not allowed: %s", path)
        print("Error: Absolute paths are not allowed.")
        return

    # 3.  Optional:  Restrict allowed file extensions (allowlist).  This is highly recommended.
    allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif']  # Example allowlist
    _, file_extension = os.path.splitext(path)
    if file_extension.lower() not in allowed_extensions:
        logging.error("Invalid file extension: %s", file_extension)
        print("Error: Invalid file extension. Only .jpg, .jpeg, .png, and .gif are allowed.")
        return

    # 4.  Optional:  Restrict allowed directories.  This is also highly recommended.
    # Example: Only allow deletion from an 'images' subdirectory.
    allowed_directory = "images"
    if not path.startswith(allowed_directory + os.sep) and path != allowed_directory: #os.sep handles different OS path separators
        logging.error("Path not in allowed directory: %s", path)
        print(f"Error: Path must be within the '{allowed_directory}' directory.")
        return

    # Construct the full path (relative to the current working directory).
    full_path = os.path.join(os.getcwd(), path)

    # Check if the file exists before attempting to delete it.
    if os.path.exists(full_path):
        try:
            # Use os.remove() to delete the file.
            os.remove(full_path)
            logging.info("Image deleted successfully: %s", full_path)
            print(f"Image '{path}' deleted successfully.") # Inform the user (optional)
        except OSError as e:
            logging.error("Error deleting image: %s - %s", full_path, e)
            print(f"Error deleting image '{path}': {e}") # Inform the user (optional)
    else:
        logging.warning("Image not found: %s", full_path)
        print(f"Image '{path}' not found.") # Inform the user (optional)


if __name__ == '__main__':
    # Example usage (for testing):
    # Create a dummy image file for testing.
    test_image_path = "images/test_image.png"  # Relative path within the 'images' directory
    os.makedirs("images", exist_ok=True) # Create the directory if it doesn't exist
    with open(test_image_path, "w") as f:
        f.write("Dummy image content")

    delete_image(test_image_path)

    # Test with an invalid path (path traversal).
    delete_image("../test_image.png")

    # Test with an absolute path (should be rejected).
    delete_image(os.path.abspath(test_image_path))

    # Test with an invalid file extension.
    delete_image("images/test_image.txt")

    # Test with a path outside the allowed directory
    delete_image("test_image.png")

