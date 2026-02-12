import os
import fcntl
import stat
import secrets
import logging
import string  # For character whitelisting (example)

# Configure logging to a secure location (e.g., system log)
logging.basicConfig(filename='/var/log/config_creator.log', level=logging.ERROR)


def create_and_write_config(filename=None, content=None):
    """
    Creates a file with highly restrictive permissions and writes content to it securely.
    Uses a random filename if none is provided.

    Args:
        filename (str, optional): The name of the file to create/write to. If None, a random filename is generated.
        content (str, optional): The content to write to the file. If None, a random string is generated.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """

    if filename is None:
        filename = f".config_{secrets.token_hex(8)}"  # Hidden file with random name
    if content is None:
        content = secrets.token_urlsafe(32)  # Generate random content

    try:
        # Define permissions: owner read/write only
        permissions = stat.S_IRUSR | stat.S_IWUSR

        # Open the file with O_CREAT, O_EXCL, and specified permissions
        # O_EXCL prevents race conditions by failing if the file already exists
        fd = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_EXCL, permissions)

        try:
            # Acquire an exclusive lock to prevent race conditions
            fcntl.flock(fd, fcntl.LOCK_EX)

            # Validate and sanitize the content (example: basic length check)
            if not isinstance(content, str):
                raise ValueError("Content must be a string.")
            if len(content) > 4096:  # Example: Limit content length
                raise ValueError("Content is too long.")

            # Example: Whitelist allowed characters (alphanumeric and some punctuation)
            allowed_chars = string.ascii_letters + string.digits + ".,-_"
            if not all(c in allowed_chars for c in content):
                raise ValueError("Content contains invalid characters.")

            # Write the content to the file
            os.write(fd, content.encode('utf-8'))  # Encode to bytes

            # Ensure data is written to disk
            os.fsync(fd)

        finally:
            # Release the lock and close the file descriptor
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

        return True

    except FileExistsError:
        logging.error(f"File already exists: {filename}")
        return False
    except OSError as e:
        logging.error(f"Error creating/writing to file: {e}")
        return False
    except ValueError as e:
        logging.error(f"Invalid content: {e}")
        return False


if __name__ == "__main__":
    if create_and_write_config():
        print("Configuration file created and written successfully.")
    else:
        print("Failed to create and write configuration file.")

    # Example of reading the file (for verification) - only if you know the filename
    # This is intentionally commented out to avoid accidental exposure of the file
    # try:
    #     with open(".config_random", "r") as f:  # Replace with the actual filename
    #         content = f.read()
    #         print(f"Content of the file: {content}")
    # except FileNotFoundError:
    #     print("File not found.")
    # except Exception as e:
    #     print(f"Error reading file: {e}")

