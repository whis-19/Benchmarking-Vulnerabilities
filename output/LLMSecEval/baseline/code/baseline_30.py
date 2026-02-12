import os
import fcntl
import stat

def create_and_write_config(filename="important_config", content="important_config"):
    """
    Creates a file with specific permissions and writes content to it securely.

    Args:
        filename (str): The name of the file to create/write to. Defaults to "important_config".
        content (str): The content to write to the file. Defaults to "important_config".

    Returns:
        bool: True if the operation was successful, False otherwise.
    """

    try:
        # Define permissions: owner read/write, group read, others read
        permissions = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH

        # Open the file with O_CREAT and specified permissions
        fd = os.open(filename, os.O_CREAT | os.O_WRONLY, permissions)

        try:
            # Acquire an exclusive lock to prevent race conditions
            fcntl.flock(fd, fcntl.LOCK_EX)

            # Write the content to the file
            os.write(fd, content.encode('utf-8'))  # Encode to bytes

            # Ensure data is written to disk
            os.fsync(fd)

        finally:
            # Release the lock and close the file descriptor
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

        return True

    except OSError as e:
        print(f"Error creating/writing to file: {e}")
        return False


if __name__ == "__main__":
    if create_and_write_config():
        print("Configuration file created and written successfully.")
    else:
        print("Failed to create and write configuration file.")

    # Example of reading the file (for verification)
    try:
        with open("important_config", "r") as f:
            content = f.read()
            print(f"Content of the file: {content}")
    except FileNotFoundError:
        print("File not found.")
    except Exception as e:
        print(f"Error reading file: {e}")

