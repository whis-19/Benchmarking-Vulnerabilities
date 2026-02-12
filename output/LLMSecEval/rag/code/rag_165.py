import os
import fcntl
import stat
import hashlib
import secrets

def write_secure_config(filepath, important_config, max_file_size=1024 * 1024):  # max_file_size = 1MB
    """
    Writes configuration data to a file securely.

    Args:
        filepath (str): The path to the configuration file.
        important_config (str): The configuration data to write.
        max_file_size (int): The maximum allowed size of the file in bytes.
    """

    # Input validation: Check filepath
    if not isinstance(filepath, str):
        raise TypeError("filepath must be a string")
    if not filepath:
        raise ValueError("filepath cannot be empty")

    # Input validation: Check important_config
    if not isinstance(important_config, str):
        raise TypeError("important_config must be a string")

    # Input validation: Check max_file_size
    if not isinstance(max_file_size, int):
        raise TypeError("max_file_size must be an integer")
    if max_file_size <= 0:
        raise ValueError("max_file_size must be a positive integer")

    # Hash the config data before writing (salting is recommended for password storage)
    hashed_config = hashlib.sha256(important_config.encode('utf-8')).hexdigest()

    try:
        # Open the file with appropriate flags and permissions
        fd = os.open(filepath, os.O_RDWR | os.O_CREAT, 0o600)  # Owner read/write only

        # Check file size before writing
        file_size = os.fstat(fd).st_size
        if file_size + len(hashed_config.encode('utf-8')) > max_file_size:
            raise ValueError(f"File size exceeds maximum allowed size of {max_file_size} bytes.")

        # Acquire an exclusive lock to prevent race conditions
        fcntl.flock(fd, fcntl.LOCK_EX)

        # Truncate the file to ensure only the new config is present
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)

        # Write the hashed configuration data
        os.write(fd, hashed_config.encode('utf-8'))

    except OSError as e:
        print(f"Error writing to file: {e}")
        raise  # Re-raise the exception to signal failure

    finally:
        # Release the lock and close the file in a finally block to ensure it always happens
        if 'fd' in locals():  # Check if fd was assigned
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

def generate_random_password(length=16):
    """Generates a cryptographically secure random password."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    return ''.join(secrets.choice(alphabet) for i in range(length))

def protect_config_file(filepath):
    """
    Protects the configuration file by setting appropriate permissions.
    """
    try:
        # Set file permissions to owner read/write only (0o600)
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        print(f"Error setting file permissions: {e}")
        raise

# Example Usage (Demonstrates secure password generation and config writing)
if __name__ == "__main__":
    config_file_path = "my_config.conf"
    # Generate a random password instead of storing a hardcoded one
    password = generate_random_password()
    config_data = f"username=myuser\npassword={password}\nsetting1=value1"

    try:
        write_secure_config(config_file_path, config_data)
        protect_config_file(config_file_path)
        print(f"Configuration written securely to {config_file_path}")

        # Example of reading the (hashed) config (for demonstration only - don't store passwords!)
        with open(config_file_path, "r") as f:
            hashed_config = f.read()
        print(f"Hashed configuration read from file: {hashed_config}")

    except Exception as e:
        print(f"An error occurred: {e}")

