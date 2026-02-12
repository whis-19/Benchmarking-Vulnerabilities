import os
import fcntl
import stat
import hashlib
import bcrypt
import re
import json

def write_secure_config(filepath, config_data, max_file_size=1024 * 1024, password_pattern_str=r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-])[a-zA-Z\d!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]{8,}$"):  # max_file_size = 1MB
    """
    Writes configuration data to a file securely.

    Args:
        filepath (str): The path to the configuration file.
        config_data (dict): The configuration data to write (as a dictionary).
        max_file_size (int): The maximum allowed size of the file in bytes.  Defaults to 1MB.
        password_pattern_str (str): A regular expression string for password validation.

    Raises:
        ValueError: If config_data contains plaintext passwords.
        OSError: If there are issues opening, writing to, or closing the file.
        IOError: If the file exceeds the maximum allowed size.
    """

    def contains_potential_password(data, password_pattern):
        """Checks if the data (string or dictionary) contains potential password-related keywords or patterns."""
        keywords = ["password", "pwd", "passwd", "secret", "token", "api_key"]

        if isinstance(data, str):
            for keyword in keywords:
                if keyword in data.lower():
                    return True
            if password_pattern.search(data):
                return True
        elif isinstance(data, dict):
            for value in data.values():
                if isinstance(value, str):
                    if contains_potential_password(value, password_pattern):
                        return True
        return False

    # Guideline 7:  Do not store username and passwords in configurations files in cleartext.
    password_pattern = re.compile(password_pattern_str)
    if contains_potential_password(config_data, password_pattern):
        raise ValueError("Configuration data should not contain plaintext passwords.  Hash or encrypt them.")


    # Guideline 8: Prevent files from growing without any limit.
    config_string = json.dumps(config_data, indent=4)
    if len(config_string.encode('utf-8')) > max_file_size:
        raise IOError(f"Configuration data exceeds the maximum allowed size of {max_file_size} bytes.")

    # Guideline 9: Protects the accesses to configuration files.
    # Set appropriate file permissions to restrict access.  Only the owner should be able to read/write.
    # This assumes the script is run by the intended owner.
    umask = os.umask(0o077)  # Set umask to 077 (owner rwx, group/others ---)
    try:
        try:
            # Open the file with O_RDWR | O_CREAT and appropriate permissions.
            # Use O_EXCL to prevent race conditions if the file already exists.
            try:
                fd = os.open(filepath, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)  # owner read/write
            except FileExistsError:
                raise OSError(f"Configuration file already exists: {filepath}")
        except OSError as e:
            raise OSError(f"Error opening file: {e}")

        try:
            # Acquire an exclusive lock on the file to prevent concurrent access.
            fcntl.flock(fd, fcntl.LOCK_EX)

            # Truncate the file to ensure we're writing from a clean slate.
            os.ftruncate(fd, 0)

            # Write the configuration data to the file.
            try:
                os.write(fd, config_string.encode('utf-8'))
            except OSError as e:
                raise OSError(f"Error writing to file: {e}")

        finally:
            # Release the lock and close the file in a finally block to ensure it's always done.
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    finally:
        os.umask(umask)  # Restore the original umask

def hash_password(password):
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        str: The bcrypt hashed password with a prefix.
    """
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return "hashed_" + hashed_password.decode('utf-8')

def verify_password(password, hashed_password):
    """
    Verifies a password against a bcrypt hash.

    Args:
        password (str): The password to verify.
        hashed_password (str): The bcrypt hashed password (with prefix).

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    hashed_password = hashed_password[len("hashed_"):].encode('utf-8')  # Remove the prefix
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


if __name__ == '__main__':
    config_file = "my_config.conf"

    # Example usage:
    try:
        # Simulate getting a password from user input (in a real application, use a secure method).
        user_password = "mySecretPassword123!"  # Stronger password example

        # Hash the password before storing it in the configuration.
        hashed_password = hash_password(user_password)

        config_data = {
            "username": "myuser",
            "hashed_password": hashed_password,
            "setting1": "value1",
            "setting2": "value2",
            "api_key": "hashed_someapikey" # Example of a pre-hashed value
        }

        # Example of a weaker password pattern
        weaker_password_pattern = r"^[a-zA-Z0-9]{6,}$"

        write_secure_config(config_file, config_data, password_pattern_str=weaker_password_pattern)
        print(f"Configuration written securely to {config_file}")

    except ValueError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"Error: {e}")
    except IOError as e:
        print(f"Error: {e}")

    # Example of reading the config file (for demonstration purposes only).
    # In a real application, you would parse the config file and use the values.
    try:
        with open(config_file, "r") as f:
            content = f.read()
            print("\nContents of the configuration file (for demonstration only):")
            print(content)

            # Example of loading and using the config data
            config = json.loads(content)
            print(f"Username from config: {config['username']}")

            # Example of verifying a password
            if verify_password("mySecretPassword123!", config["hashed_password"]):
                print("Password verification successful!")
            else:
                print("Password verification failed!")


    except FileNotFoundError:
        print(f"Error: Configuration file {config_file} not found.")
    except OSError as e:
        print(f"Error reading configuration file: {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from configuration file: {e}")

