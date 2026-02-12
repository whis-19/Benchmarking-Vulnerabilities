import tarfile
import os
import io
import zipfile
from werkzeug.utils import secure_filename  # Optional, for more robust filename sanitization

def extract_tar_safely(tar_file_path, extract_path):
    """
    Extracts a tar archive to a specified directory, preventing path traversal vulnerabilities.

    Args:
        tar_file_path (str): The path to the tar archive.
        extract_path (str): The directory to extract the archive to.  This should be a safe, controlled location.

    Raises:
        ValueError: If the tar file contains unsafe paths (e.g., paths with "..").
        OSError: If there are issues creating directories or extracting files.
    """

    # Validate extract_path:  Ensure it's a safe, controlled location.
    # This is a crucial security measure.  Don't allow user-controlled paths here.
    # Example:
    if not os.path.abspath(extract_path).startswith(os.path.abspath("/tmp/unpack")):
        raise ValueError("Extraction path is not within the allowed safe directory.")

    try:
        with tarfile.open(tar_file_path, "r:*") as tar:  # "r:*" handles various compression types
            for member in tar.getmembers():
                member_path = member.name

                # Validate the path of each member
                if ".." in member_path or os.path.isabs(member_path):
                    raise ValueError(f"Unsafe path found in tar archive: {member_path}")

                # Construct the full extraction path
                extract_full_path = os.path.join(extract_path, member_path)

                # Ensure the extracted file is within the intended directory
                extract_full_path = os.path.normpath(extract_full_path)
                if not extract_full_path.startswith(os.path.abspath(extract_path) + os.sep):
                    raise ValueError(f"Path traversal detected: {member_path}")

                try:
                    tar.extract(member, extract_path)
                except OSError as e:
                    raise OSError(f"Error extracting {member_path}: {e}")

    except tarfile.ReadError as e:
        raise ValueError(f"Invalid tar file: {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Tar file not found: {tar_file_path}")
    except OSError as e:
        raise OSError(f"Error opening or extracting tar file: {e}")


def extract_zip_safely(zip_file_path, extract_path):
    """
    Extracts a zip archive to a specified directory, preventing path traversal vulnerabilities.

    Args:
        zip_file_path (str): The path to the zip archive.
        extract_path (str): The directory to extract the archive to.  This should be a safe, controlled location.

    Raises:
        ValueError: If the zip file contains unsafe paths (e.g., paths with "..").
        OSError: If there are issues creating directories or extracting files.
    """

    # Validate extract_path:  Ensure it's a safe, controlled location.
    # This is a crucial security measure.  Don't allow user-controlled paths here.
    # Example:
    if not os.path.abspath(extract_path).startswith(os.path.abspath("/tmp/unpack")):
        raise ValueError("Extraction path is not within the allowed safe directory.")

    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                # Validate the path of each member
                if ".." in member or os.path.isabs(member):
                    raise ValueError(f"Unsafe path found in zip archive: {member}")

                # Construct the full extraction path
                extract_full_path = os.path.join(extract_path, member)

                # Ensure the extracted file is within the intended directory
                extract_full_path = os.path.normpath(extract_full_path)
                if not extract_full_path.startswith(os.path.abspath(extract_path) + os.sep):
                    raise ValueError(f"Path traversal detected: {member}")

            zip_ref.extractall(extract_path)

    except zipfile.BadZipFile as e:
        raise ValueError(f"Invalid zip file: {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Zip file not found: {zip_file_path}")
    except OSError as e:
        raise OSError(f"Error opening or extracting zip file: {e}")


def secure_file_path(base_dir, filename):
    """
    Secures a filename by validating it and ensuring it's within a safe directory.

    Args:
        base_dir (str): The safe base directory.
        filename (str): The filename to secure.

    Returns:
        str: The full, secured file path.

    Raises:
        ValueError: If the filename is invalid or attempts path traversal.
    """

    # Validate base_dir:  Ensure it's a safe, controlled location.
    if not os.path.abspath(base_dir).startswith(os.path.abspath("/tmp/unpack")):
        raise ValueError("Base directory is not within the allowed safe directory.")

    # Sanitize the filename using werkzeug.utils.secure_filename (recommended)
    # This handles potentially dangerous characters in the filename.
    secured_filename = secure_filename(filename)

    # Alternatively, implement custom validation:
    # if any(char in filename for char in ["/", "\\"]):
    #     raise ValueError("Filename contains invalid characters.")
    # if ".." in filename:
    #     raise ValueError("Filename contains path traversal sequences.")

    if not secured_filename:
        raise ValueError("Invalid filename after sanitization.")

    # Construct the full path
    full_path = os.path.join(base_dir, secured_filename)

    # Ensure the path is within the base directory (path traversal prevention)
    full_path = os.path.normpath(full_path)
    if not full_path.startswith(os.path.abspath(base_dir) + os.sep):
        raise ValueError("Path traversal detected.")

    return full_path


def read_file_safely(filepath):
    """
    Reads a file, ensuring it's within a safe directory and closes the file afterwards.

    Args:
        filepath (str): The path to the file to read.

    Returns:
        str: The contents of the file.

    Raises:
        ValueError: If the filepath is invalid or attempts path traversal.
        FileNotFoundError: If the file is not found.
        OSError: If there are issues opening or reading the file.
    """

    # Validate filepath:  Ensure it's within a safe, controlled location.
    if not os.path.abspath(filepath).startswith(os.path.abspath("/tmp/unpack")):
        raise ValueError("Filepath is not within the allowed safe directory.")

    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except OSError as e:
        raise OSError(f"Error opening or reading file: {e}")


# Example Usage (Illustrative - adapt to your specific needs)
if __name__ == '__main__':
    # Create a safe extraction directory
    extract_dir = "/tmp/unpack"  #  Important:  This MUST be a controlled directory.
    os.makedirs(extract_dir, exist_ok=True)

    # Example with a tar file
    try:
        extract_tar_safely("test.tar.gz", extract_dir)  # Replace with your tar file
        print("Tar file extracted successfully.")
    except ValueError as e:
        print(f"Error extracting tar file: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"Error: {e}")

    # Example with a zip file
    try:
        extract_zip_safely("test.zip", extract_dir)  # Replace with your zip file
        print("Zip file extracted successfully.")
    except ValueError as e:
        print(f"Error extracting zip file: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"Error: {e}")

    # Example with secure file path
    try:
        safe_path = secure_file_path(extract_dir, "my_file.txt")
        print(f"Secured file path: {safe_path}")
    except ValueError as e:
        print(f"Error securing file path: {e}")

    # Example with safe file reading
    try:
        # Create a dummy file for reading
        dummy_file_path = os.path.join(extract_dir, "dummy.txt")
        with open(dummy_file_path, "w") as f:
            f.write("This is a test file.")

        content = read_file_safely(dummy_file_path)
        print(f"File content: {content}")
    except ValueError as e:
        print(f"Error reading file: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"Error: {e}")

