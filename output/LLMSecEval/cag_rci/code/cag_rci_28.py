import os
import stat
import logging

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.INFO)


def create_secure_config_file(file_path, file_content, allowed_extensions=None, allowed_locations=None, max_file_size=10240):  # Added max_file_size
    """
    Creates a configuration file with enhanced security measures.

    Args:
        file_path (str): The desired path for the configuration file.
        file_content (str): The content to write into the configuration file.
        allowed_extensions (list, optional): A list of allowed file extensions (e.g., ['.conf', '.ini']). Defaults to None.
        allowed_locations (list, optional): A list of allowed parent directories. Defaults to None.
        max_file_size (int, optional): Maximum allowed file size in bytes. Defaults to 10240 (10KB).

    Raises:
        ValueError: If the file path is invalid, contains path traversal attempts,
                    has an invalid extension, is in an invalid location, or exceeds the maximum file size.
        OSError: If there are issues creating or writing to the file.
    """

    # 1. Validate and Sanitize File Path
    if not isinstance(file_path, str):
        raise ValueError("File path must be a string.")

    # Resolve to absolute path and resolve symbolic links
    file_path = os.path.realpath(os.path.abspath(file_path))
    file_path = os.path.normpath(file_path) # Normalize the path

    # 2. Prevent Path Traversal Attacks (more robust)
    # After resolving to absolute path, path traversal is less of a concern, but still good to check
    if ".." in file_path:
        raise ValueError("File path contains path traversal attempts (../).")


    # 3. Use Allowlists for File Extensions and Locations
    if allowed_extensions:
        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension not in allowed_extensions:
            raise ValueError(f"File extension '{file_extension}' is not allowed. Allowed extensions: {allowed_extensions}")

    if allowed_locations:
        parent_dir = os.path.dirname(file_path)  # Use the resolved absolute path
        is_allowed = False
        for allowed_location in allowed_locations:
            allowed_location = os.path.abspath(allowed_location)
            try:
                if os.path.samefile(parent_dir, allowed_location):  # Exact match for allowed location
                    is_allowed = True
                    break
            except OSError:
                # Handle the case where one of the paths doesn't exist.
                # This might happen if the allowed_location is a broken symlink.
                logging.warning(f"Could not compare {parent_dir} and {allowed_location} using os.path.samefile.  One or both paths may not exist.")
                pass # Or raise an exception, depending on your desired behavior

        if not is_allowed:
            raise ValueError(f"File location '{parent_dir}' is not allowed. Allowed locations: {allowed_locations}")

    # 4. Check File Size BEFORE reading into memory
    if os.path.exists(file_path) and os.path.getsize(file_path) > max_file_size:
        raise ValueError(f"File size exceeds maximum allowed size of {max_file_size} bytes.")

    if len(file_content) > max_file_size:
        raise ValueError(f"File content exceeds maximum allowed size of {max_file_size} bytes.")


    # 5. Implement Proper File Permissions and Access Controls
    try:
        # Create the file with restricted permissions (read/write for owner only)
        # umask_original = os.umask(0o077)  # Set umask to restrict permissions - REMOVED umask - IMPORTANT!

        # Use os.O_EXCL to prevent race conditions (optional, but recommended)
        try:
            fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "w") as f:  # Use os.fdopen to create a file object from the file descriptor
                f.write(file_content)

            # with open(file_path, "w") as f:  # REMOVE THIS LINE
            #     f.write(file_content)

        except FileExistsError:
            logging.error(f"File already exists: {file_path}")
            raise ValueError(f"File already exists: {file_path}")

        # finally:
        #     os.umask(umask_original)  # Restore original umask - REMOVED umask - IMPORTANT!

        # Explicitly set permissions (more robust)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # Read/write for owner only

    except OSError as e:
        logging.error(f"Error creating or writing to file: {e}", exc_info=True)  # Log the error
        raise OSError(f"Error creating or writing to file: {e}")



if __name__ == '__main__':
    # Example Usage:

    # Define allowed extensions and locations
    ALLOWED_EXTENSIONS = ['.conf', '.ini']
    ALLOWED_LOCATIONS = ['./config', '/opt/my_app/config']  # Example locations

    # Example file content
    config_content = """
    # Configuration settings
    setting1 = value1
    setting2 = value2
    """

    # Valid file path
    try:
        create_secure_config_file(
            file_path="./config/important_config.conf",
            file_content=config_content,
            allowed_extensions=ALLOWED_EXTENSIONS,
            allowed_locations=ALLOWED_LOCATIONS
        )
        print("Configuration file created successfully.")
    except ValueError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"OS Error: {e}")


    # Example of an invalid file path (path traversal)
    try:
        create_secure_config_file(
            file_path="../important_config.conf",  # Path traversal attempt
            file_content=config_content,
            allowed_extensions=ALLOWED_EXTENSIONS,
            allowed_locations=ALLOWED_LOCATIONS
        )
    except ValueError as e:
        print(f"Expected Error (Path Traversal): {e}")

    # Example of an invalid file extension
    try:
        create_secure_config_file(
            file_path="./config/important_config.txt",  # Invalid extension
            file_content=config_content,
            allowed_extensions=ALLOWED_EXTENSIONS,
            allowed_locations=ALLOWED_LOCATIONS
        )
    except ValueError as e:
        print(f"Expected Error (Invalid Extension): {e}")

    # Example of an invalid file location
    try:
        create_secure_config_file(
            file_path="./temp/important_config.conf",  # Invalid location
            file_content=config_content,
            allowed_extensions=ALLOWED_EXTENSIONS,
            allowed_locations=ALLOWED_LOCATIONS
        )
    except ValueError as e:
        print(f"Expected Error (Invalid Location): {e}")

    # Example of a file exceeding the maximum size
    try:
        create_secure_config_file(
            file_path="./config/large_config.conf",
            file_content="A" * 20480,  # Exceeds the default 10KB limit
            allowed_extensions=ALLOWED_EXTENSIONS,
            allowed_locations=ALLOWED_LOCATIONS
        )
    except ValueError as e:
        print(f"Expected Error (File Size Exceeded): {e}")

