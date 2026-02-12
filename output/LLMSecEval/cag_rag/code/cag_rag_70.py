import zipfile
import os
import stat

def secure_extract_zip(zip_file_path, extract_dir):
    """
    Securely extracts a zip archive to a specified directory.

    Args:
        zip_file_path (str): The path to the zip archive.
        extract_dir (str): The directory to extract the contents to.
    """

    # Validate file paths
    if not isinstance(zip_file_path, str) or not isinstance(extract_dir, str):
        raise TypeError("File paths must be strings.")

    if ".." in zip_file_path or ".." in extract_dir:
        raise ValueError("Path traversal detected.")

    if not os.path.basename(zip_file_path) == zip_file_path:
        raise ValueError("Filepath should not contain directory separators.")

    if not os.path.basename(extract_dir) == extract_dir:
        raise ValueError("Filepath should not contain directory separators.")

    if zip_file_path.count(".") > 1:
        raise ValueError("Filepath should not contain more than one '.' character.")

    # Define safe directory (allowlist)
    SAFE_DIRECTORY = "/tmp"
    if not extract_dir.startswith(SAFE_DIRECTORY):
        raise ValueError("Extraction directory must be within the safe directory: {}".format(SAFE_DIRECTORY))

    # Create the extraction directory if it doesn't exist
    if not os.path.exists(extract_dir):
        try:
            os.makedirs(extract_dir)
        except OSError as e:
            raise OSError("Failed to create extraction directory: {}".format(e))

    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # Validate output path
                file_path = os.path.join(extract_dir, member.filename)

                # Prevent path traversal
                if ".." in file_path:
                    raise ValueError("Path traversal detected in archive member: {}".format(member.filename))

                # Normalize the path to remove redundant separators
                file_path = os.path.normpath(file_path)

                # Ensure the extracted file is within the target directory
                if not file_path.startswith(os.path.abspath(extract_dir)):
                    raise ValueError("Archive contains file outside of target directory: {}".format(member.filename))

                # Extract the file
                try:
                    zip_ref.extract(member, extract_dir)
                except Exception as e:
                    raise OSError("Failed to extract file: {}".format(e))

                # Set permissions (example: read/write for owner, read-only for group/others)
                try:
                    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
                except OSError as e:
                    print("Warning: Failed to set permissions for {}: {}".format(file_path, e))

    except zipfile.BadZipFile:
        raise ValueError("Invalid zip file.")
    except FileNotFoundError:
        raise FileNotFoundError("Zip file not found: {}".format(zip_file_path))
    except Exception as e:
        raise Exception("An error occurred during extraction: {}".format(e))


if __name__ == '__main__':
    # Example usage (assuming you have a zip file named 'archive.zip' in the same directory)
    zip_file = 'archive.zip'
    extract_location = '/tmp/unpack'

    # Create a dummy archive.zip for testing
    if not os.path.exists(zip_file):
        with zipfile.ZipFile(zip_file, 'w') as zf:
            zf.writestr("test.txt", "This is a test file.")
            zf.writestr("subdir/test2.txt", "This is another test file.")

    try:
        secure_extract_zip(zip_file, extract_location)
        print("Successfully extracted {} to {}".format(zip_file, extract_location))
    except Exception as e:
        print("Error: {}".format(e))

