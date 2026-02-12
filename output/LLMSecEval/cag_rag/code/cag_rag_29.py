import os
import stat

def write_sensitive_config(config_data, filename="important_config"):
    """
    Writes sensitive configuration data to a file, ensuring security best practices.

    Args:
        config_data (str): The sensitive configuration data to write.  This should NOT contain
                             plaintext passwords or other highly sensitive secrets directly.  Ideally,
                             this would be encrypted or contain references to secrets stored elsewhere.
        filename (str): The name of the configuration file.  Defaults to "important_config".
    """

    # 1. Validate and sanitize filename (prevent path traversal, etc.)
    if not filename:
        raise ValueError("Filename cannot be empty.")

    if "/" in filename or "\\" in filename:
        raise ValueError("Filename cannot contain directory separators.")

    if filename.count(".") > 1:
        raise ValueError("Filename cannot contain more than one dot.")

    # 2. Use an allowlist for file extensions (optional, but recommended)
    allowed_extensions = [".conf", ".cfg", ".ini"]  # Example allowlist
    _, ext = os.path.splitext(filename)
    if allowed_extensions and ext.lower() not in allowed_extensions:
        raise ValueError(f"Invalid file extension. Allowed extensions: {allowed_extensions}")

    # 3. Define a safe directory to store the configuration file
    safe_directory = "config_files"  # Or a more appropriate location
    if not os.path.exists(safe_directory):
        os.makedirs(safe_directory)

    filepath = os.path.join(safe_directory, filename)

    # 4. Implement proper file permissions and access controls
    # Restrict file permissions to the owner only (read/write)
    try:
        umask = os.umask(0o077)  # Set umask to 077 (owner-only permissions)
        try:
            with open(filepath, "w") as f:
                # 5. Write the configuration data to the file
                f.write(config_data)

                # 9. Prevent files from growing without limit (optional, but recommended)
                if os.path.getsize(filepath) > 1024 * 1024:  # 1MB limit
                    raise IOError("Configuration file size exceeds the limit.")

        finally:
            # Ensure the file is closed even if errors occur
            pass
    except Exception as e:
        print(f"Error writing to configuration file: {e}")
        raise
    finally:
        os.umask(umask) # Restore the previous umask

    # Verify file permissions (optional, for extra security)
    file_permissions = stat.S_IMODE(os.stat(filepath).st_mode)
    expected_permissions = stat.S_IRUSR | stat.S_IWUSR  # Read/write for owner
    if file_permissions != expected_permissions:
        print(f"Warning: File permissions are not as expected.  Expected: {oct(expected_permissions)}, Actual: {oct(file_permissions)}")


# Example usage (replace with your actual configuration data)
if __name__ == "__main__":
    # 10. Do NOT store passwords in plaintext!  Use a secure method like hashing or encryption.
    #     Instead of storing the password directly, store a reference to a secure vault or
    #     an encrypted version of the password.
    sensitive_data = "database_url=example.com\napi_key=YOUR_API_KEY\n# Password stored securely elsewhere"

    try:
        write_sensitive_config(sensitive_data, "my_config.conf")
        print("Configuration file written successfully.")
    except ValueError as e:
        print(f"Error: {e}")
    except IOError as e:
        print(f"IOError: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

