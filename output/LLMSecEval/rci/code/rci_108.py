import os
import stat
import tempfile
import logging

# Configure logging (basic example)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def create_and_secure_file(content="U2FsdGVkX1/R+WzJcxgvX/Iw=="):
    """
    Creates a file in a secure temporary location, writes content to it,
    sets restrictive permissions, and returns the file path.

    Args:
        content (str): The content to write to the file.

    Returns:
        str: The path to the created file.  None if an error occurred.
    """

    filepath = None  # Initialize filepath to None
    try:
        # Create a secure temporary file with restrictive permissions
        fd, filepath = tempfile.mkstemp()  # Creates with 0o600 permissions by default
        logging.info(f"Created temporary file: {filepath}")

        # Write the content to the file
        with os.fdopen(fd, "w") as f:
            f.write(content)
        logging.info(f"Wrote content to file: {filepath}")

        # Verify permissions (optional, but good practice)
        permissions = stat.filemode(os.stat(filepath).st_mode)
        logging.info(f"Permissions of {filepath}: {permissions}")

        return filepath

    except OSError as e:
        logging.error(f"Error: Could not create or modify file: {e}")
        return None
    finally:
        if filepath:
            try:
                os.remove(filepath)
                logging.info(f"Successfully removed {filepath}")
            except OSError as e:
                logging.error(f"Error removing {filepath}: {e}")


if __name__ == "__main__":
    file_path = create_and_secure_file()
    if file_path:
        print(f"Secure file created at: {file_path}")
        # Clean up the file after use (important for temporary files)
        # os.remove(file_path) # Uncomment when done with the file - now handled in try...finally
    else:
        print("File creation failed.")

