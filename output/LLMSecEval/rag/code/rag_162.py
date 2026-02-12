import os
import stat
import logging

# Configure logging (important for auditing and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def write_config_securely(filename="important_config", config_data="important_config", max_file_size_kb=1024):  # Added max_file_size
    """
    Writes configuration data to a file securely.

    Args:
        filename (str): The name of the configuration file.
        config_data (str): The configuration data to write.  This should ideally be encrypted.
        max_file_size_kb (int): Maximum file size in KB to prevent unlimited growth.
    """

    try:
        # 1. Protect access to configuration files: Restrict permissions.
        #   - Only the owner (e.g., the user running the application) should have read/write access.
        #   - Group and others should have no access.
        file_permissions = stat.S_IRUSR | stat.S_IWUSR  # Owner read/write

        # Check if the file exists and its size before writing
        if os.path.exists(filename):
            file_size_kb = os.path.getsize(filename) / 1024
            if file_size_kb > max_file_size_kb:
                logging.error(f"File {filename} exceeds maximum allowed size ({max_file_size_kb} KB).  Write aborted.")
                return  # Or raise an exception if appropriate

        # Open the file with restricted permissions.  The 'x' mode ensures the file is created only if it doesn't exist.
        # If the file exists, it will raise a FileExistsError, preventing accidental overwrites.
        # We use a temporary file and rename it to avoid partial writes.
        temp_filename = filename + ".tmp"
        try:
            with open(temp_filename, "x") as f:  # 'x' mode for exclusive creation
                f.write(config_data)
                f.flush()  # Ensure data is written to disk
                os.fsync(f.fileno()) # Ensure data is written to disk
        except FileExistsError:
            logging.warning(f"File {filename} already exists.  Not overwriting.")
            return

        # Set permissions *after* writing to the temporary file, but *before* renaming.
        os.chmod(temp_filename, file_permissions)

        # Atomically rename the temporary file to the final filename.  This prevents data corruption if the process is interrupted.
        os.replace(temp_filename, filename)

        logging.info(f"Configuration data written securely to {filename}")

    except Exception as e:
        logging.error(f"Error writing configuration data to {filename}: {e}")
        # Handle the exception appropriately (e.g., retry, alert administrator)
    finally:
        # Ensure the temporary file is cleaned up if an error occurred before renaming.
        if os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except OSError as e:
                logging.error(f"Failed to remove temporary file {temp_filename}: {e}")


# Example usage:
if __name__ == "__main__":
    # In a real application, 'sensitive_config_data' should be encrypted.
    sensitive_config_data = "This is sensitive data that should be encrypted before writing to disk."

    # Ideally, encrypt the data before writing it to the file.
    # For example, using a library like cryptography:
    # from cryptography.fernet import Fernet
    # key = Fernet.generate_key()  # Store this key securely!
    # cipher = Fernet(key)
    # encrypted_data = cipher.encrypt(sensitive_config_data.encode())
    # write_config_securely("my_config.txt", encrypted_data.decode())

    # For demonstration purposes, we'll write the data as is (but this is NOT recommended for sensitive data).
    write_config_securely("my_config.txt", sensitive_config_data)

    # Example of exceeding the file size limit
    # write_config_securely("large_config.txt", "A" * (2 * 1024 * 1024), max_file_size_kb=1) # Try to write 2MB to a file with 1KB limit

