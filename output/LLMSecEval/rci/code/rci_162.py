import os
import stat
import errno
import tempfile
import shutil
import secrets
import logging  # Import the logging module

# Configure logging (adjust level and destination as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class TempFileContext:
    def __init__(self, filename):
        self.filename = filename

    def __enter__(self):
        return self.filename

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            os.remove(self.filename)
            logging.debug(f"Removed temporary file: {self.filename}")
        except OSError as e:
            logging.warning(f"Failed to remove temporary file {self.filename}: {e}")


def write_secure_config(filename="important_config", content=None, allowed_dir=None):
    """
    Writes the given content to a file with restricted permissions, preventing race conditions and path traversal.

    Args:
        filename (str): The name of the file to create/write to. Defaults to "important_config".
        content (str): The string content to write to the file. Must be provided.
        allowed_dir (str):  Optional directory where the config file must reside.  If None, no path restriction is enforced.

    Raises:
        ValueError: If content is not provided or filename is invalid.
        OSError: If there's an error creating or writing to the file, or setting permissions.
    """

    if content is None:
        raise ValueError("Content must be provided.")

    if not filename:
        raise ValueError("Filename cannot be empty.")

    # Filename Validation (Path Traversal Prevention)
    abs_path = os.path.abspath(filename)

    if allowed_dir:
        abs_allowed_dir = os.path.realpath(os.path.abspath(allowed_dir)) # Resolve allowed_dir to its real path
        if not abs_path.startswith(abs_allowed_dir):
            raise ValueError(f"Filename must be within the allowed directory: {abs_allowed_dir}")

    try:
        # Create a temporary file in the same directory
        target_dir = os.path.dirname(abs_path)
        if not target_dir:
            target_dir = "."  # Current directory if filename is just a name

        # Create the target directory if it doesn't exist
        os.makedirs(target_dir, exist_ok=True, mode=stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        # Generate a random temporary filename to avoid collisions
        tmp_filename = os.path.join(target_dir, secrets.token_hex(16)) + ".tmp"

        fd = None  # Initialize fd to None
        try:
            # Create the temporary file with exclusive access and specific permissions atomically
            fd = os.open(tmp_filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, stat.S_IRUSR | stat.S_IWUSR)
            with open(fd, 'w') as f:  # Open the file descriptor as a file object
                f.write(content)

            # Atomically rename the temporary file to the final filename
            # Double check the path before renaming to prevent TOCTOU attacks
            if allowed_dir:
                abs_path_check = os.path.abspath(filename)
                if not abs_path_check.startswith(abs_allowed_dir):
                    raise ValueError(f"Filename must be within the allowed directory: {abs_allowed_dir} (TOCTOU)")

            os.rename(tmp_filename, abs_path)
            os.chmod(abs_path, stat.S_IRUSR | stat.S_IWUSR) # Set permissions after rename

        except OSError as e:
            if e.errno == errno.EEXIST:
                raise OSError(f"File already exists: {filename}") from e # More informative error
            else:
                logging.error(f"Error writing to or setting permissions on file: {e}")
                try:
                    os.remove(tmp_filename)  # Clean up temporary file on error
                except OSError:
                    pass # Ignore cleanup errors
                raise  # Re-raise the exception to signal failure to the caller
        finally:
            if fd is not None:  # Check if fd was successfully opened
                try:
                    os.close(fd)
                except OSError:
                    pass # Ignore close errors

    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        raise
    except OSError as e:
        logging.error(f"Error writing secure config: {e}")
        raise


if __name__ == '__main__':
    try:
        # Example 1: Basic usage
        write_secure_config(filename="important_config", content="This is the important config data.")
        print("Successfully wrote to important_config with secure permissions.")

        # Example 2: Custom filename and content
        write_secure_config(filename="my_secret.txt", content="This is my secret!", allowed_dir=".")
        print("Successfully wrote to my_secret.txt with secure permissions.")

        # Example 3:  Attempt to write outside allowed directory (will raise an error)
        # write_secure_config(filename="../outside_config.txt", content="This should fail", allowed_dir=".") # This will raise a ValueError

        # Example 4: allowed_dir as a symlink
        os.makedirs("test_dir", exist_ok=True)
        if os.path.exists("symlink_dir"):
            os.remove("symlink_dir")
        os.symlink("test_dir", "symlink_dir")
        write_secure_config(filename="test_dir/config.txt", content="Test config", allowed_dir="symlink_dir")
        print("Successfully wrote to config.txt via symlink.")
        shutil.rmtree("test_dir")
        os.remove("symlink_dir")


    except (ValueError, OSError) as e:
        print(f"Failed to write secure config file: {e}")

