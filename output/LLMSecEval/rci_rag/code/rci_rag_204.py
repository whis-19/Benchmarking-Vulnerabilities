import tarfile
import os
import io
import zipfile
from werkzeug.utils import secure_filename
import logging
import stat

logging.basicConfig(level=logging.INFO)  # Configure logging

def is_safe_path(base, path):
    """
    Checks if a given path is safe to access within a base directory.
    Uses realpath to resolve symlinks.
    """
    try:
        base = os.path.realpath(base)
        path = os.path.realpath(path)
        return base == os.path.commonpath((base, path))
    except ValueError:
        return False

def ensure_directory_exists(path, mode=0o755):
    """Ensures a directory exists with the specified permissions."""
    try:
        os.makedirs(path, exist_ok=True)  # exist_ok=True prevents errors if the directory already exists
        os.chmod(path, mode)
    except OSError as e:
        logging.error(f"Error creating directory {path}: {e}")

def set_file_permissions(file_path, mode=0o644):
    """Sets file permissions."""
    try:
        os.chmod(file_path, mode)
    except Exception as e:
        logging.error(f"Error setting permissions for {file_path}: {e}")


def extract_tarfile_safely(tar_file_path, extract_path, max_size_bytes=None, max_files=None):
    """
    Extracts a tarfile to a specified directory, preventing path traversal vulnerabilities.
    Handles symlinks and hard links by extracting them as regular files.
    Limits the total extracted size to prevent resource exhaustion.

    Args:
        tar_file_path (str): The path to the tarfile.
        extract_path (str): The directory to extract the contents to.
        max_size_bytes (int, optional): The maximum total size of extracted files in bytes.
                                         Defaults to None (no limit).
        max_files (int, optional): The maximum number of files to extract. Defaults to None (no limit).
    """

    # Validate extract_path to ensure it's a safe directory
    if not is_safe_path(extract_path, extract_path):
        raise ValueError("Invalid extract path: {}".format(extract_path))

    extracted_size = 0
    extracted_files = 0

    try:
        with tarfile.open(tar_file_path, 'r') as tar:
            for member in tar.getmembers():
                # Sanitize the member name to prevent path traversal
                member_path = secure_filename(member.name)
                if not member_path:
                    logging.warning(f"Skipping member with invalid filename: {member.name}")
                    continue

                # Handle symlinks and hard links by extracting them as regular files
                if member.issym() or member.ishard():
                    logging.warning(f"Found symlink or hardlink: {member.name}.  Extracting as regular file.")
                    member.type = tarfile.REGTYPE  # Extract as regular file

                # Construct the full extraction path
                extract_full_path = os.path.join(extract_path, member_path)

                # Validate the extraction path before extraction
                if not is_safe_path(extract_path, extract_full_path):
                    raise ValueError("Attempted to extract to unsafe path: {}".format(extract_full_path))

                # Check for size limits before extraction
                if max_size_bytes is not None:
                    if member.isfile():
                        if extracted_size + member.size > max_size_bytes:
                            raise ValueError(f"Exceeded maximum extraction size.  Current size: {extracted_size}, Member size: {member.size}, Max size: {max_size_bytes}")
                        extracted_size += member.size

                # Check for file count limits
                if max_files is not None and extracted_files >= max_files:
                    raise ValueError(f"Exceeded maximum number of files: {max_files}")

                try:
                    tar.extract(member, extract_path)
                    full_extracted_path = os.path.join(extract_path, member_path)
                    if member.isdir():
                        set_file_permissions(full_extracted_path, mode=0o755)  # Example: drwxr-xr-x
                    else:
                        set_file_permissions(full_extracted_path, mode=0o644)  # Example: -rw-r--r--
                    extracted_files += 1
                    logging.info(f"Extracted {member.name} to {full_extracted_path}")

                except Exception as e:
                    logging.error(f"Error extracting {member.name}: {e}")
                    continue  # Continue to the next member

    except tarfile.ReadError as e:
        raise ValueError(f"Could not open tarfile: {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Tarfile not found: {tar_file_path}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred: {e}")


def extract_zipfile_safely(zip_file_path, extract_path, max_size_bytes=None, max_files=None):
    """
    Extracts a zipfile to a specified directory, preventing path traversal vulnerabilities.
    Limits the total extracted size to prevent resource exhaustion.

    Args:
        zip_file_path (str): The path to the zipfile.
        extract_path (str): The directory to extract the contents to.
        max_size_bytes (int, optional): The maximum total size of extracted files in bytes.
                                         Defaults to None (no limit).
        max_files (int, optional): The maximum number of files to extract. Defaults to None (no limit).
    """

    # Validate extract_path to ensure it's a safe directory
    if not is_safe_path(extract_path, extract_path):
        raise ValueError("Invalid extract path: {}".format(extract_path))

    extracted_size = 0
    extracted_files = 0

    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # Sanitize the member name to prevent path traversal
                member_path = secure_filename(member.filename)
                if not member_path:
                    logging.warning(f"Skipping member with invalid filename: {member.filename}")
                    continue

                # Construct the full extraction path
                extract_full_path = os.path.join(extract_path, member_path)

                # Validate the extraction path before extraction
                if not is_safe_path(extract_path, extract_full_path):
                    raise ValueError("Attempted to extract to unsafe path: {}".format(extract_full_path))

                # Check for size limits before extraction
                if max_size_bytes is not None:
                    if extracted_size + member.file_size > max_size_bytes:
                        raise ValueError(f"Exceeded maximum extraction size.  Current size: {extracted_size}, Member size: {member.file_size}, Max size: {max_size_bytes}")
                    extracted_size += member.file_size

                # Check for file count limits
                if max_files is not None and extracted_files >= max_files:
                    raise ValueError(f"Exceeded maximum number of files: {max_files}")

                try:
                    zip_ref.extract(member, extract_path)
                    full_extracted_path = os.path.join(extract_path, member_path)
                    # Zip files don't have directory entries, so we need to check if the path ends with a slash
                    if member.filename.endswith('/'):
                        set_file_permissions(full_extracted_path, mode=0o755)
                    else:
                        set_file_permissions(full_extracted_path, mode=0o644)
                    extracted_files += 1
                    logging.info(f"Extracted {member.filename} to {full_extracted_path}")

                except Exception as e:
                    logging.error(f"Error extracting {member.filename}: {e}")
                    continue  # Continue to the next member

    except zipfile.BadZipFile as e:
        raise ValueError(f"Could not open zipfile: {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Zipfile not found: {zip_file_path}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred: {e}")


def is_safe_path(base, path):
    """
    Checks if a given path is safe to access within a base directory.
    Uses realpath to resolve symlinks.
    """
    try:
        base = os.path.realpath(base)
        path = os.path.realpath(path)
        return base == os.path.commonpath((base, path))
    except ValueError:
        return False

def secure_file_creation(file_path, content, safe_dir):
    """
    Creates a file securely within a safe directory.

    Args:
        file_path (str): The desired file path (filename only, no directories).
        content (str): The content to write to the file.
        safe_dir (str): The safe directory where the file should be created.
    """

    # Validate the safe directory
    if not os.path.isdir(safe_dir):
        raise ValueError("Safe directory does not exist: {}".format(safe_dir))

    # Sanitize the filename using werkzeug.utils.secure_filename
    filename = secure_filename(file_path)
    if not filename:
        raise ValueError("Invalid filename: {}".format(file_path))

    # Construct the full file path
    full_file_path = os.path.join(safe_dir, filename)

    # Validate the full file path
    if not is_safe_path(safe_dir, full_file_path):
        raise ValueError("Attempted to create file outside of safe directory.")

    try:
        with open(full_file_path, 'w') as f:
            f.write(content)
    except Exception as e:
        raise Exception(f"Error creating file: {e}")


def validate_filepath(filepath):
    """
    Validates a filepath to ensure it is safe.  Rejects paths with directory separators or ".." sequences.

    Args:
        filepath (str): The filepath to validate.

    Returns:
        str: The validated filepath if it is safe.

    Raises:
        ValueError: If the filepath is invalid.
    """

    if "/" in filepath or "\\" in filepath:
        raise ValueError("Filepath cannot contain directory separators.")

    if ".." in filepath:
        raise ValueError("Filepath cannot contain '..' sequences.")

    return filepath  # Return the original filepath if it passes validation


# Example of setting file permissions (after extraction)
def set_file_permissions(file_path, mode=0o644):
    """Sets file permissions."""
    try:
        os.chmod(file_path, mode)
    except Exception as e:
        logging.error(f"Error setting permissions for {file_path}: {e}")


# Example Usage (Illustrative - replace with your actual file paths and content)
if __name__ == '__main__':
    # Ensure the extraction directory exists with proper permissions
    ensure_directory_exists("/tmp/unpack")
    ensure_directory_exists("/tmp/safe_dir")

    # Tarfile example
    try:
        extract_tarfile_safely("example.tar.gz", "/tmp/unpack", max_size_bytes=1024 * 1024 * 100, max_files=1000)  # 100MB limit, 1000 files
        print("Tarfile extracted successfully.")
    except ValueError as e:
        print(f"Error extracting tarfile: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    # Zipfile example
    try:
        extract_zipfile_safely("example.zip", "/tmp/unpack", max_size_bytes=1024 * 1024 * 100, max_files=1000)  # 100MB limit, 1000 files
        print("Zipfile extracted successfully.")
    except ValueError as e:
        print(f"Error extracting zipfile: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    # Secure file creation example
    try:
        secure_file_creation("my_file.txt", "This is some content.", "/tmp/safe_dir") # Replace with your desired filename, content, and safe directory
        print("File created successfully.")
    except ValueError as e:
        print(f"Error creating file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    # Filepath validation example
    try:
        validated_path = validate_filepath("safe_file.txt")
        print(f"Filepath '{validated_path}' is valid.")
    except ValueError as e:
        print(f"Error: {e}")

    try:
        validate_filepath("../unsafe_file.txt")  # This will raise a ValueError
    except ValueError as e:
        print(f"Error: {e}")

