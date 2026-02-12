import zipfile
import os
import os.path

def secure_extract_zip(zip_file_path, extract_dir):
    """
    Securely extracts a zip file to a specified directory.

    Args:
        zip_file_path (str): The path to the zip file.
        extract_dir (str): The directory to extract the contents to.
    """

    # Security Guideline 1, 10, 12, 13, 14: Validate and sanitize file paths
    if not isinstance(zip_file_path, str) or not isinstance(extract_dir, str):
        raise TypeError("File paths must be strings.")

    if ".." in zip_file_path or "/" in zip_file_path or "\\" in zip_file_path:
        raise ValueError("Invalid characters in zip file path.")

    if ".." in extract_dir or "/" in extract_dir or "\\" in extract_dir:
        raise ValueError("Invalid characters in extract directory path.")

    if zip_file_path.count(".") > 1:
        raise ValueError("Invalid zip file path: too many '.' characters.")

    # Security Guideline 11: Filepath should be contained within a safe folder
    # In this example, we assume /tmp is a safe folder.  In a real application,
    # you would need to define what constitutes a "safe" folder based on your
    # environment and security policies.  This is a placeholder.
    if not extract_dir.startswith("/tmp"):
        raise ValueError("Extract directory must be within /tmp.")

    # Security Guideline 2: Prevent path traversal attacks
    # Security Guideline 3: Use allowlists for file extensions and locations
    # Security Guideline 4: Implement proper file permissions and access controls
    # Security Guideline 5, 6, 7, 8: Validate output paths constructed from archive entries
    # Security Guideline 9: Ensure that an opened file it is always closed on exiting the method.

    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # Validate output path
                file_path = os.path.join(extract_dir, member.filename)
                file_path = os.path.normpath(file_path)  # Normalize the path

                if not file_path.startswith(extract_dir):
                    raise ValueError("Path traversal attempt detected.")

                # Check for directory traversal in the filename itself
                if ".." in member.filename or "/" in member.filename or "\\" in member.filename:
                    raise ValueError("Invalid characters in filename within zip archive.")

                # Allowlist of allowed file extensions (example)
                allowed_extensions = ['.txt', '.pdf', '.csv', '.png', '.jpg', '.jpeg']
                _, file_extension = os.path.splitext(member.filename)
                if file_extension.lower() not in allowed_extensions:
                    print(f"Skipping file with disallowed extension: {member.filename}")
                    continue

                # Create the directory if it doesn't exist
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                # Extract the file
                zip_ref.extract(member, extract_dir)

                # Implement proper file permissions (example - adjust as needed)
                os.chmod(file_path, 0o644)  # Read/write for owner, read-only for others

    except FileNotFoundError:
        print(f"Error: Zip file not found at {zip_file_path}")
        raise
    except zipfile.BadZipFile:
        print(f"Error: Invalid zip file at {zip_file_path}")
        raise
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise

if __name__ == '__main__':
    # Example usage:
    zip_file = 'archive.zip'  # Replace with your zip file
    extract_location = '/tmp/unpack'

    # Create a dummy zip file for testing
    if not os.path.exists(zip_file):
        with zipfile.ZipFile(zip_file, 'w') as zf:
            zf.writestr("test.txt", "This is a test file.")
            zf.writestr("safe/test2.txt", "This is another test file in a subdirectory.")
            # Attempted path traversal (will be blocked)
            # zf.writestr("../../../evil.txt", "This should not be extracted.")

    try:
        secure_extract_zip(zip_file, extract_location)
        print(f"Successfully extracted {zip_file} to {extract_location}")
    except ValueError as e:
        print(f"Security error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

