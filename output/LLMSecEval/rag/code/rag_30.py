import os
import fcntl
import stat
import logging
import secrets
import hashlib

# Configure logging (important for auditing and debugging, especially with sensitive data)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_and_write_config(filepath="important_config"):
    """
    Creates a configuration file with restricted permissions and writes a string to it.

    Security Considerations Addressed:
    - **File Permissions (Guideline 9, 10):**  Sets restrictive permissions (owner read/write, group read, others read)
    - **File Creation (Guideline 2):** Ensures the file is closed properly.
    - **Sensitive Data (Guideline 8):**  While this example writes a simple string, in a real-world scenario,
      you would *never* store passwords or sensitive data in plaintext.  This function provides a placeholder
      and highlights the need for encryption or secure storage.
    - **Error Handling:** Includes robust error handling to prevent information leaks and ensure proper cleanup.
    """

    try:
        # Use os.open with flags for atomic creation and permission setting
        fd = os.open(filepath, os.O_CREAT | os.O_WRONLY | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # O_EXCL prevents race conditions

        try:
            # Securely generate a random salt
            salt = secrets.token_hex(16)

            # Example:  Instead of storing plaintext, hash the sensitive data with a salt.
            #  This is a *minimal* security measure.  For real-world applications, use proper encryption.
            sensitive_data = "This is a placeholder for sensitive configuration data."
            hashed_data = hashlib.sha256((sensitive_data + salt).encode('utf-8')).hexdigest()

            # Construct the configuration string (including the salt)
            config_string = f"hashed_data={hashed_data}\nsalt={salt}\n"

            # Write the configuration string to the file
            os.write(fd, config_string.encode('utf-8'))
            logging.info(f"Configuration file '{filepath}' created and written successfully.")

        except Exception as e:
            logging.error(f"Error writing to configuration file: {e}")
            raise  # Re-raise the exception to be handled by the outer try-except

        finally:
            # Ensure the file is always closed
            os.close(fd)

    except FileExistsError:
        logging.warning(f"Configuration file '{filepath}' already exists.  Skipping creation.")
    except OSError as e:
        logging.error(f"Error creating configuration file: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def read_config(filepath="important_config"):
    """
    Reads the configuration file and retrieves the hashed data and salt.

    Security Considerations Addressed:
    - **File Access (Guideline 10):**  Assumes the file has restricted permissions.
    - **Error Handling:** Includes error handling to prevent information leaks.
    - **File Closing (Guideline 2):** Ensures the file is closed.
    """
    hashed_data = None
    salt = None

    try:
        with open(filepath, "r") as f:
            for line in f:
                if line.startswith("hashed_data="):
                    hashed_data = line.split("=", 1)[1].strip()
                elif line.startswith("salt="):
                    salt = line.split("=", 1)[1].strip()

        if hashed_data is None or salt is None:
            logging.warning(f"Could not find hashed_data or salt in '{filepath}'.")
            return None, None

        logging.info(f"Configuration file '{filepath}' read successfully.")
        return hashed_data, salt

    except FileNotFoundError:
        logging.error(f"Configuration file '{filepath}' not found.")
        return None, None
    except OSError as e:
        logging.error(f"Error reading configuration file: {e}")
        return None, None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None, None


def verify_data(data_to_verify, hashed_data, salt):
    """
    Verifies data against the stored hash using the salt.

    This is a *minimal* security measure.  For real-world applications, use proper encryption.
    """
    if hashed_data is None or salt is None:
        logging.error("Hashed data or salt is missing. Cannot verify.")
        return False

    calculated_hash = hashlib.sha256((data_to_verify + salt).encode('utf-8')).hexdigest()
    return calculated_hash == hashed_data


if __name__ == "__main__":
    filepath = "important_config"

    # Create and write the configuration file
    create_and_write_config(filepath)

    # Read the configuration file
    hashed_data, salt = read_config(filepath)

    if hashed_data and salt:
        # Example: Verify some data
        data_to_verify = "This is a placeholder for sensitive configuration data."
        if verify_data(data_to_verify, hashed_data, salt):
            logging.info("Data verification successful!")
        else:
            logging.warning("Data verification failed!")
    else:
        logging.warning("Could not read configuration data. Verification skipped.")

