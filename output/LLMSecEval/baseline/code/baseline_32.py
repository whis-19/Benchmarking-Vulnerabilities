import os
import fcntl
import stat
import errno

def write_secure_config(filepath, config_data, owner_uid, owner_gid):
    """
    Writes configuration data to a file securely, ensuring proper permissions and ownership.

    Args:
        filepath (str): The path to the configuration file.
        config_data (str): The configuration data to write.
        owner_uid (int): The user ID (UID) of the file owner.
        owner_gid (int): The group ID (GID) of the file owner.

    Raises:
        OSError: If any error occurs during file creation, writing, or permission setting.
    """

    # Create the file with O_CREAT | O_RDWR | O_EXCL and mode 0600
    # O_EXCL ensures that the file is created only if it doesn't exist, preventing race conditions.
    # 0600 permissions restrict access to the owner only (read/write).
    try:
        fd = os.open(filepath, os.O_CREAT | os.O_RDWR | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise OSError(f"File already exists: {filepath}.  Refusing to overwrite.") from e
        else:
            raise OSError(f"Error creating file: {filepath}") from e

    try:
        # Lock the file to prevent concurrent access.  fcntl.LOCK_EX is exclusive lock.
        fcntl.flock(fd, fcntl.LOCK_EX)

        # Truncate the file to zero length before writing.  This prevents data leakage if the new config is shorter than the old.
        os.ftruncate(fd, 0)

        # Write the configuration data to the file.
        os.write(fd, config_data.encode('utf-8'))  # Encode to bytes

        # Ensure data is written to disk immediately.
        os.fsync(fd)

    except OSError as e:
        raise OSError(f"Error writing to file: {filepath}") from e

    finally:
        # Release the lock and close the file descriptor.  Crucially, do this in a finally block.
        try:
            if 'fd' in locals(): # Check if fd was successfully opened before attempting to unlock/close
                fcntl.flock(fd, fcntl.LOCK_UN)  # Release the lock
                os.close(fd)
        except OSError as e:
            print(f"Error releasing lock or closing file: {e}") # Log the error, but don't re-raise.  We've already written the data.

    # Set the ownership of the file.  Do this *after* writing the data.
    try:
        os.chown(filepath, owner_uid, owner_gid)
    except OSError as e:
        raise OSError(f"Error setting ownership of file: {filepath}") from e

    # Set the permissions of the file to 0600.  Do this *after* setting ownership.
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        raise OSError(f"Error setting permissions of file: {filepath}") from e


if __name__ == '__main__':
    # Example usage:
    filepath = "important_config.txt"
    important_config = "This is a very important configuration setting.\nSecret key: mysecretkey123"

    # Get the current user's UID and GID.  Replace with the appropriate UID/GID for your application.
    owner_uid = os.geteuid()
    owner_gid = os.getgid()

    try:
        write_secure_config(filepath, important_config, owner_uid, owner_gid)
        print(f"Configuration written securely to {filepath}")
    except OSError as e:
        print(f"Error: {e}")

