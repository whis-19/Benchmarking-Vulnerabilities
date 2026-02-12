import os
import fcntl
import stat
import hashlib
import secrets

def write_secure_config(filepath, config_data, max_file_size=1024 * 1024):  # max_file_size = 1MB
    """
    Writes configuration data to a file securely.

    Args:
        filepath (str): The path to the configuration file.
        config_data (dict): A dictionary containing the configuration data.  Values should be strings.
        max_file_size (int): The maximum allowed size of the configuration file in bytes.
    """

    # Input validation: Check filepath
    if not isinstance(filepath, str):
        raise TypeError("filepath must be a string")

    # Input validation: Check config_data
    if not isinstance(config_data, dict):
        raise TypeError("config_data must be a dictionary")
    for key, value in config_data.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("config_data keys and values must be strings")

    # Securely serialize the configuration data.  Use a format that's easy to parse and secure.
    # JSON is a good option, but for simplicity, we'll use a simple key=value format.
    # IMPORTANT:  Avoid using pickle or other serialization formats that can be exploited.
    config_string = ""
    for key, value in config_data.items():
        config_string += f"{key}={value}\n"

    # Hash the password before storing it
    if "password" in config_data:
        hashed_password = hashlib.sha256(config_data["password"].encode()).hexdigest()
        config_string = config_string.replace(f"password={config_data['password']}", f"password={hashed_password}")

    # Check file size before writing
    if len(config_string.encode('utf-8')) > max_file_size:
        raise ValueError(f"Configuration data exceeds maximum allowed size of {max_file_size} bytes.")

    # Generate a temporary file name in the same directory to prevent TOCTOU race conditions.
    temp_filepath = os.path.join(os.path.dirname(filepath), f".{os.path.basename(filepath)}.tmp.{secrets.token_hex(8)}")

    try:
        # Open the temporary file with appropriate flags and permissions.
        fd = os.open(temp_filepath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # Only owner can read/write
        # O_EXCL prevents race conditions if the file already exists.
        # 0o600 ensures only the owner can read/write.

        try:
            # Write the configuration data to the temporary file.
            os.write(fd, config_string.encode('utf-8'))

            # Atomically rename the temporary file to the final file.
            os.rename(temp_filepath, filepath)

        finally:
            # Ensure the file descriptor is always closed.
            os.close(fd)

    except FileExistsError:
        # Handle the case where the temporary file already exists (very unlikely).
        print("Error: Temporary file already exists.  This is unexpected.")
        # Consider logging this event.
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath) # Clean up the temporary file if it exists.
        raise
    except Exception as e:
        # Handle other potential errors during file operations.
        print(f"Error writing configuration file: {e}")
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath) # Clean up the temporary file if it exists.
        raise

    finally:
        # Ensure the temporary file is cleaned up if it exists and wasn't renamed.
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)

def read_secure_config(filepath):
    """
    Reads configuration data from a file securely.

    Args:
        filepath (str): The path to the configuration file.

    Returns:
        dict: A dictionary containing the configuration data.
    """

    # Input validation: Check filepath
    if not isinstance(filepath, str):
        raise TypeError("filepath must be a string")

    config_data = {}
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:  # Ignore empty lines
                    try:
                        key, value = line.split("=", 1)  # Split only on the first '='
                        config_data[key] = value
                    except ValueError:
                        print(f"Warning: Invalid line in config file: {line}")  # Log invalid lines
    except FileNotFoundError:
        print(f"Warning: Configuration file not found: {filepath}")
        return {}  # Return an empty dictionary if the file doesn't exist
    except Exception as e:
        print(f"Error reading configuration file: {e}")
        raise

    return config_data


# Example Usage:
if __name__ == "__main__":
    config_file = "my_config.conf"
    config_data = {
        "username": "myuser",
        "password": "mysecretpassword",
        "api_key": "some_api_key"
    }

    try:
        write_secure_config(config_file, config_data)
        print(f"Configuration written to {config_file}")

        read_config = read_secure_config(config_file)
        print(f"Configuration read from {config_file}: {read_config}")

        # Verify password hash
        if "password" in read_config:
            hashed_password = hashlib.sha256(config_data["password"].encode()).hexdigest()
            if read_config["password"] == hashed_password:
                print("Password hash verified successfully.")
            else:
                print("Password hash verification failed.")

    except Exception as e:
        print(f"An error occurred: {e}")

