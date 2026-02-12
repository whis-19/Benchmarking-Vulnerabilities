import os
import fcntl
import stat
import hashlib
import bcrypt  # Import bcrypt library

def write_secure_config(filepath, config_data, max_file_size=1024 * 1024):  # max_file_size = 1MB
    """
    Writes configuration data to a file securely.

    Args:
        filepath (str): The path to the configuration file.
        config_data (str): The configuration data to write.  Should NOT contain plaintext passwords.
        max_file_size (int): The maximum allowed size of the file in bytes.  Defaults to 1MB.

    Raises:
        OSError: If there's an error opening or writing to the file.
        ValueError: If the config_data is too large.
    """

    if len(config_data.encode('utf-8')) > max_file_size:
        raise ValueError("Configuration data exceeds maximum allowed size.")

    # Hash the config data before writing (salting is recommended for real passwords)
    hashed_config = hashlib.sha256(config_data.encode('utf-8')).hexdigest()

    fd = None  # Initialize fd to None
    try:
        # Open the file with appropriate flags and permissions
        # Use os.O_EXCL to prevent race condition on file creation
        fd = os.open(filepath, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)  # Read/write, create if not exists, permissions: rw-------

        # Lock the file to prevent concurrent access
        fcntl.flock(fd, fcntl.LOCK_EX)

        # Truncate the file to ensure it doesn't exceed the maximum size
        os.ftruncate(fd, 0)

        # Write the hashed configuration data
        os.write(fd, hashed_config.encode('utf-8'))

    except OSError as e:
        print(f"Error writing to file: {e}")
        raise  # Re-raise the exception to be handled by the caller
    except FileExistsError:
        print(f"Error: File already exists: {filepath}.  Race condition on file creation likely.")
        raise

    finally:
        # Release the lock and close the file in a finally block to ensure it always happens
        if fd is not None:  # Check if fd was assigned
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)  # Release the lock
                os.close(fd)
            except OSError as e:
                print(f"Error releasing lock or closing file: {e}")


def verify_config_file_permissions(filepath):
    """
    Verifies that the configuration file has secure permissions (read/write only for the owner).

    Args:
        filepath (str): The path to the configuration file.

    Returns:
        bool: True if the permissions are secure, False otherwise.
    """
    try:
        file_stat = os.stat(filepath)
        permissions = stat.S_IMODE(file_stat.st_mode)  # Extract permission bits

        # Check if permissions are 0o600 (rw-------)
        if permissions == 0o600:
            return True
        else:
            print(f"Warning: Insecure file permissions for {filepath}. Permissions are: {oct(permissions)}")
            try:
                os.chmod(filepath, 0o600)
                print(f"Attempted to correct permissions to 0o600 for {filepath}")
            except OSError as e:
                print(f"Error correcting file permissions: {e}")
            return False

    except FileNotFoundError:
        print(f"Warning: File not found: {filepath}")
        return False
    except OSError as e:
        print(f"Error checking file permissions: {e}")
        return False


def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

def verify_password(password, hashed_password):
    """Verifies a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


if __name__ == '__main__':
    config_file = "my_config.conf"
    sensitive_data = "This is some important configuration data.  DO NOT STORE PASSWORDS HERE."

    try:
        write_secure_config(config_file, sensitive_data)
        print(f"Configuration data written securely to {config_file}")

        if verify_config_file_permissions(config_file):
            print(f"File permissions for {config_file} are secure.")
        else:
            print(f"File permissions for {config_file} are NOT secure.  Please investigate.")

    except ValueError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"Error: {e}")
    except FileExistsError as e:
        print(f"Error: {e}")

    # Example usage of bcrypt for password hashing
    password = "mysecretpassword"
    hashed = hash_password(password)
    print(f"Hashed password: {hashed}")

    if verify_password(password, hashed):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")

