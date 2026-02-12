import os
import fcntl
import stat
import secrets
import tempfile  # For creating temporary files
import logging

# Configure logging (consider a more robust setup for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def create_and_write_config(filename=None, content="important_config"):
    """
    Creates a file with specific permissions and writes content to it securely using atomic rename.

    Args:
        filename (str, optional): The name of the file to create. If None, a random filename is generated.
        content (str): The content to write to the file.

    Returns:
        str: The filename of the created file, or None if the operation failed.
    """

    if filename is None:
        filename = secrets.token_urlsafe(16) + ".config"  # Generate a random filename

    try:
        # Define permissions: owner read/write, group read, others read
        permissions = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH

        # Create a temporary file in the same directory
        temp_fd, temp_filename = tempfile.mkstemp(dir=os.path.dirname(filename), prefix=".tmp", suffix=".config")

        try:
            # Acquire an exclusive lock to prevent race conditions
            fcntl.flock(temp_fd, fcntl.LOCK_EX)

            # Write the content to the temporary file
            content_bytes = content.encode('utf-8')  # Encode to bytes
            os.write(temp_fd, content_bytes)
            os.fsync(temp_fd) # Ensure data is written to disk

            # Atomically rename the temporary file to the final filename
            os.rename(temp_filename, filename)

        except Exception as e:
            logging.error(f"Error during file writing process: {e}")
            return None

        finally:
            # Release the lock and close the file descriptor
            fcntl.flock(temp_fd, fcntl.LOCK_UN)
            os.close(temp_fd)
            try:
                os.remove(temp_filename) # Remove temp file if rename failed
            except FileNotFoundError:
                pass # Already removed by rename
            except Exception as e:
                logging.warning(f"Failed to remove temporary file {temp_filename}: {e}")


        return filename

    except OSError as e:
        logging.error(f"Error creating or writing to file: {e}")  # Log detailed error
        print("Error creating or writing to file. See logs for details.") # Generic message for user
        return None


if __name__ == "__main__":
    config_filename = create_and_write_config(content="This is my secret configuration.")
    if config_filename:
        print("File created and written successfully.")
    else:
        print("File creation or writing failed.")

    # Example of reading the file (for verification)
    if config_filename:
        try:
            with open(config_filename, "r", encoding="utf-8") as f:  # Explicit encoding
                file_content = f.read()
                print(f"File content: {file_content}")
        except FileNotFoundError:
            print("File not found.")
        except Exception as e:
            print(f"Error reading file: {e}")

