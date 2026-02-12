import os
import stat
import tempfile
import logging
import errno

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_secure_config_file(filepath="important_config", base_dir="/tmp"):
    """
    Creates a file with restricted permissions, suitable for storing sensitive configuration data,
    using a temporary file and atomic rename for increased robustness.

    Args:
        filepath (str, optional): The path to the file to create. Defaults to "important_config".
        base_dir (str, optional): The base directory where the config file should reside.

    Raises:
        OSError: If there's an error creating or setting permissions on the file.
    """

    try:
        # 1. Sanitize and validate filepath
        filepath = os.path.abspath(filepath)  # Normalize the path
        if not filepath.startswith(base_dir):
            raise ValueError(f"Filepath must be within the base directory: {base_dir}")

        # 2. Create the directory if it doesn't exist
        dirpath = os.path.dirname(filepath)
        try:
            os.makedirs(dirpath, exist_ok=True)
        except OSError as e:
            logging.error(f"Error creating directory: {e}")
            raise

        # 3. Create a temporary file in the same directory
        with tempfile.NamedTemporaryFile(mode='w', dir=dirpath, delete=False) as tmpfile:
            tmp_filepath = tmpfile.name

            # 4. Set permissions on the temporary file *before* writing to it.
            os.fchmod(tmpfile.fileno(), stat.S_IRUSR | stat.S_IWUSR)  # User read/write only (0o600)

            # 5. Write the configuration data to the temporary file
            tmpfile.write("# This is a secure configuration file.\n")
            tmpfile.write("# Only the owner should be able to read or write this file.\n")
            tmpfile.write("# Add your configuration settings here.\n")

            # 6. Ensure all data is written to disk before renaming
            tmpfile.flush()
            os.fsync(tmpfile.fileno())

        # 7. Atomically rename the temporary file to the final filepath.
        os.rename(tmp_filepath, filepath)

        logging.info(f"Secure configuration file created at: {filepath}")

    except FileExistsError:
        logging.warning(f"File already exists: {filepath}.  Consider deleting it or using a different name.")
    except OSError as e:
        logging.error(f"Error creating or securing the file: {e}")
    except ValueError as e:
        logging.error(f"Invalid filepath: {e}")
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Log the full traceback
        # Optionally, re-raise the exception if you want it to propagate
        # raise


if __name__ == "__main__":
    create_secure_config_file(filepath="/tmp/my_config.conf", base_dir="/tmp")
    create_secure_config_file(filepath="my_config.conf", base_dir="/tmp") # Example of a valid filepath
    create_secure_config_file(filepath="/etc/passwd", base_dir="/tmp") # Example of an invalid filepath

