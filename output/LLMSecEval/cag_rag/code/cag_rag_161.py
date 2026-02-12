import os
import stat
import secrets
import hashlib

# Define a safe directory for configuration files
CONFIG_DIR = "/opt/app/config"  # Or another appropriate location

# Maximum file size (in bytes) to prevent unbounded growth
MAX_FILE_SIZE = 1024 * 1024  # 1MB

def create_secure_config_file(filename="important_config"):
    """
    Creates a configuration file with restricted permissions and secure content handling.
    """

    # 1. Validate and sanitize filename
    if not filename:
        raise ValueError("Filename cannot be empty.")

    if "/" in filename or "\\" in filename:
        raise ValueError("Filename cannot contain directory separators.")

    if filename.count(".") > 1:
        raise ValueError("Filename cannot contain more than one dot.")

    # Create the full file path within the safe directory
    filepath = os.path.join(CONFIG_DIR, filename)

    # 2. Prevent path traversal attacks (double-check after joining)
    if not os.path.abspath(filepath).startswith(os.path.abspath(CONFIG_DIR)):
        raise ValueError("Invalid filename: Path traversal detected.")

    # 3.  File extension allowlist (optional, but recommended)
    allowed_extensions = [".conf", ".cfg"]  # Example
    _, ext = os.path.splitext(filename)
    if allowed_extensions and ext.lower() not in allowed_extensions:
        raise ValueError(f"Invalid file extension. Allowed extensions: {allowed_extensions}")

    # Generate a secure, random API key (example of sensitive data)
    api_key = secrets.token_hex(32)  # 32 bytes = 64 hex characters

    # Hash the API key before storing it (best practice)
    hashed_api_key = hashlib.sha256(api_key.encode('utf-8')).hexdigest()

    # Construct the configuration content (avoid storing passwords directly)
    config_content = f"""
    # This is a sensitive configuration file.  Handle with care.
    # API Key (hashed): {hashed_api_key}
    # Other configuration parameters...
    """

    # 4. Implement proper file permissions and access controls
    try:
        # Create the directory if it doesn't exist
        os.makedirs(CONFIG_DIR, exist_ok=True)

        # Open the file with exclusive creation flag (prevents race conditions)
        fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only
        with open(fd, 'w') as f:
            # 10. Prevent files from growing without any limit
            if len(config_content.encode('utf-8')) > MAX_FILE_SIZE:
                raise ValueError(f"Configuration content exceeds maximum allowed size ({MAX_FILE_SIZE} bytes).")

            f.write(config_content)

    except FileExistsError:
        raise FileExistsError(f"File already exists: {filepath}")
    except OSError as e:
        raise OSError(f"Error creating or writing to file: {e}")
    finally:
        # Ensure the file is closed if an error occurs
        if 'f' in locals() and not f.closed:
            f.close()

    print(f"Secure configuration file created at: {filepath}")
    return filepath

# Example usage:
if __name__ == "__main__":
    try:
        config_file_path = create_secure_config_file("my_app.conf")
        print(f"Configuration file created successfully at: {config_file_path}")
    except ValueError as e:
        print(f"Error: {e}")
    except FileExistsError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"Error: {e}")

