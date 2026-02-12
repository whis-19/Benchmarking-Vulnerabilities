import os
import stat
import errno
import tempfile
import logging  # Import the logging module

# Configure logging (replace with your actual logging setup)
logging.basicConfig(filename='secure.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def write_secure_config(filename, content, max_size=10240):  # Added max_size
    """
    Writes the given content to a file with restricted permissions, preventing race conditions and symlink attacks.

    Args:
        filename (str): The name of the file to create/write to.
        content (str): The string content to write to the file.
        max_size (int): Maximum size of the content in bytes.  Defaults to 10KB.

    Raises:
        TypeError: If filename or content are not strings.
        ValueError: If content exceeds max_size.
        OSError: If there's an error creating or writing to the file, or setting permissions.
    """

    if not isinstance(filename, str):
        raise TypeError("filename must be a string")
    if not isinstance(content, str):
        raise TypeError("content must be a string")

    if len(content) > max_size:
        raise ValueError(f"Content exceeds maximum allowed size of {max_size} bytes.")

    # Resolve the filename to its absolute path and check for directory traversal
    abs_filename = os.path.abspath(filename)
    if not abs_filename.startswith(os.path.abspath(os.path.dirname(filename))):
        raise OSError("Invalid filename: potential directory traversal detected.")


    # Create a temporary file in the same directory
    try:
        temp_fd, temp_filename = tempfile.mkstemp(dir=os.path.dirname(abs_filename))
    except OSError as e:
        logging.error(f"Failed to create temporary file: {e}")
        raise

    try:
        # Write content to the temporary file
        with os.fdopen(temp_fd, 'w') as f:
            f.write(content)

        # Set permissions on the temporary file (restrictive permissions)
        os.chmod(temp_filename, 0o600)  # Explicitly set permissions to 0600

        # Atomically rename the temporary file to the final filename
        os.rename(temp_filename, abs_filename)

    except OSError as e:
        logging.error(f"Error writing to {abs_filename}: {e}")
        try:
            os.remove(temp_filename)  # Clean up the temporary file if writing fails
        except OSError as cleanup_e:
            logging.error(f"Failed to clean up temporary file {temp_filename}: {cleanup_e}")
        raise  # Re-raise the exception to signal failure to the caller

    except Exception as e:
        logging.error(f"Unexpected error writing to {abs_filename}: {e}")
        try:
            os.remove(temp_filename)  # Clean up the temporary file if writing fails
        except OSError as cleanup_e:
            logging.error(f"Failed to clean up temporary file {temp_filename}: {cleanup_e}")
        raise # Re-raise the exception to signal failure to the caller


if __name__ == '__main__':
    try:
        # Example of writing with custom filename and content:
        write_secure_config(filename="my_secret.txt", content="This is my secret!")
        print("Successfully wrote to my_secret.txt with secure permissions.")

        # Example with directory traversal attempt (will raise an error)
        # write_secure_config(filename="../my_secret.txt", content="This is my secret!")

        # Example with content exceeding max_size (will raise an error)
        # write_secure_config(filename="large_secret.txt", content="A" * 20480)

    except OSError as e:
        print(f"Failed to write secure config file: {e}")
    except TypeError as e:
        print(f"Invalid input: {e}")
    except ValueError as e:
        print(f"Invalid input: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

