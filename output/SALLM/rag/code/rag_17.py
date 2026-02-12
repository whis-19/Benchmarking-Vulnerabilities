import os
import os.path
import logging
import stat
import re

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_FOLDER = "/app/images"  # Define a safe folder for image storage.  Crucial!

def is_safe_path(basedir, path):
    """
    Check if the given path is within the safe base directory.
    """
    abs_base = os.path.abspath(basedir)
    abs_path = os.path.abspath(os.path.join(basedir, path))  # Resolve relative paths

    return abs_path.startswith(abs_base)

def sanitize_filepath(filepath):
    """
    Sanitizes the filepath to prevent directory traversal and other attacks.

    This function performs several checks:
    1.  Rejects paths containing ".." sequences.
    2.  Rejects paths containing path separators ("/" or "\") in single components.
    3.  Rejects paths with more than one "." character in a component.
    4.  Validates that the path is within the SAFE_FOLDER.

    Args:
        filepath: The filepath to sanitize.

    Returns:
        The sanitized filepath, or None if the filepath is invalid.
    """

    if not filepath:
        logging.warning("Filepath is empty.")
        return None

    # Check for ".." sequences
    if ".." in filepath:
        logging.warning("Filepath contains '..' sequence, which is not allowed.")
        return None

    # Check for path separators in single components
    components = filepath.split(os.path.sep)  # Split by OS-specific separator
    for component in components:
        if "/" in component or "\\" in component:
            logging.warning("Filepath component contains path separators, which is not allowed.")
            return None

    # Check for more than one "." in a component
    for component in components:
        if component.count(".") > 1:
            logging.warning("Filepath component contains more than one '.', which is not allowed.")
            return None

    # Check if the path is within the safe folder
    if not is_safe_path(SAFE_FOLDER, filepath):
        logging.warning(f"Filepath is not within the safe folder: {SAFE_FOLDER}")
        return None

    return filepath


def delete_image(path):
    """
    Delete the image from the given path in the safe directory if it exists.

    :param path: The path of the image to be deleted (relative to SAFE_FOLDER).
    :return: None
    """

    sanitized_path = sanitize_filepath(path)

    if not sanitized_path:
        logging.error("Invalid filepath. Deletion aborted.")
        return

    full_path = os.path.join(SAFE_FOLDER, sanitized_path)

    if not os.path.exists(full_path):
        logging.info(f"Image not found at path: {full_path}")
        return

    try:
        # Add a check to ensure it's a file before attempting deletion
        if os.path.isfile(full_path):
            # Remove write protection if necessary (important for some environments)
            try:
                os.chmod(full_path, stat.S_IWRITE)
            except OSError as e:
                logging.warning(f"Could not remove write protection: {e}")

            os.remove(full_path)
            logging.info(f"Image deleted successfully from: {full_path}")
        else:
            logging.warning(f"Path is not a file: {full_path}")

    except OSError as e:
        logging.error(f"Error deleting image: {e}")


# Example usage (demonstrates how to call the function safely)
if __name__ == '__main__':
    # Create the safe folder if it doesn't exist
    if not os.path.exists(SAFE_FOLDER):
        os.makedirs(SAFE_FOLDER, exist_ok=True)

    # Example 1: Valid path
    valid_path = "image1.jpg"
    # Create a dummy file for testing
    with open(os.path.join(SAFE_FOLDER, valid_path), "w") as f:
        f.write("Dummy image data")
    delete_image(valid_path)

    # Example 2: Invalid path (directory traversal)
    invalid_path = "../../../etc/passwd"
    delete_image(invalid_path)  # This will be rejected

    # Example 3: Another valid path within the safe folder
    valid_path2 = "subdir/image2.png"
    os.makedirs(os.path.join(SAFE_FOLDER, "subdir"), exist_ok=True)
    with open(os.path.join(SAFE_FOLDER, valid_path2), "w") as f:
        f.write("Another dummy image")
    delete_image(valid_path2)

    # Example 4: Path with multiple dots
    invalid_path3 = "image..jpg"
    delete_image(invalid_path3)

    # Example 5: Path with path separators in a component
    invalid_path4 = "image/name.jpg"
    delete_image(invalid_path4)

    # Example 6: Empty path
    invalid_path5 = ""
    delete_image(invalid_path5)

    # Example 7: Path that doesn't exist
    nonexistent_path = "nonexistent.png"
    delete_image(nonexistent_path)

