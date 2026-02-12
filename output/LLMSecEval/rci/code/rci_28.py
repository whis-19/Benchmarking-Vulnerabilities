import os
import stat
import os.path
import secrets
import errno
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def create_secure_config_file(filepath="important_config"):
    """
    Creates a file with restricted permissions, suitable for storing sensitive configuration data.

    Args:
        filepath (str, optional): The path to the file to create. Defaults to "important_config".

    Raises:
        OSError: If there's an error creating or setting permissions on the file.
    """

    # Input Validation
    if not isinstance(filepath, str):
        logging.error("Filepath must be a string.")
        raise TypeError("Filepath must be a string.")

    # Basic Path Sanitization (Example - adapt to your needs)
    if ".." in filepath or "/" in filepath:
        logging.warning("Filepath contains potentially unsafe characters.  Sanitizing (replace with _).")
        filepath = filepath.replace("..", "_").replace("/", "_")


    try:
        # Check if the user has the appropriate privileges to create the file.
        if os.geteuid() != 0:  # Check if the user is not root (UID 0)
            logging.warning("Running as non-root user. Ensure appropriate permissions are in place.")

        # Generate a cryptographically secure random filename for the temporary file
        temp_filename = filepath + "." + secrets.token_hex(16) + ".tmp"

        # Create the temporary file with exclusive access and restrictive permissions
        try:
            fd = os.open(temp_filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as e:
            if e.errno == errno.EEXIST:
                logging.error("Temporary file already exists.  Possible attack or cleanup issue.  Aborting.")
                return  # Or raise an exception if you want to stop execution
            else:
                logging.exception("Error creating temporary file:")  # Log the full exception
                raise

        try:
            # Write some initial content (optional, but good practice to initialize)
            with os.fdopen(fd, 'w') as f:
                f.write("# This is a secure configuration file.\n")
                f.write("# Only the owner should be able to read or write this file.\n")
                f.write("# Add your configuration settings here.\n")

            # Atomic Renaming
            os.rename(temp_filename, filepath)

            logging.info(f"Secure configuration file created at: {filepath}")

        except OSError as e:
            logging.exception("Error writing to or renaming the file:")
            try:
                os.unlink(temp_filename)  # Clean up the temporary file if an error occurred
            except OSError as e2:
                logging.exception("Error cleaning up temporary file:") # Log cleanup errors
            raise

        finally:
            try:
                os.close(fd)
            except OSError as e:
                logging.exception("Error closing file descriptor:")

    except FileExistsError:
        logging.warning(f"File already exists: {filepath}.  Consider deleting it or using a different name.")
    except OSError as e:
        logging.exception("Error creating or securing the file:")


# Example usage:
if __name__ == "__main__":
    create_secure_config_file()  # Creates a file named "important_config"
    # create_secure_config_file("my_secure_config.txt") # Creates a file with a different name
    # Example of calling with a potentially malicious filepath
    # create_secure_config_file("../../../sensitive_file")

