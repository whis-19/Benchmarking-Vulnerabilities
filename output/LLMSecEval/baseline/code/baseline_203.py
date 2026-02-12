import tarfile
import os
import shutil

def is_safe_path(basedir, path):
    """
    Check if a path is safe to extract to, preventing path traversal.

    Args:
        basedir (str): The base directory to extract to.
        path (str): The path to check.

    Returns:
        bool: True if the path is safe, False otherwise.
    """
    abs_basedir = os.path.abspath(basedir)
    abs_path = os.path.abspath(os.path.join(basedir, path))  # Join to normalize path

    return abs_path.startswith(abs_basedir)

def extract_tarfile_safe(archive_path, extract_path):
    """
    Safely extracts a tarfile to a specified directory, preventing path traversal.

    Args:
        archive_path (str): The path to the tarfile.
        extract_path (str): The directory to extract the contents to.

    Raises:
        FileNotFoundError: If the archive file does not exist.
        OSError: If there are issues creating the extraction directory.
        tarfile.ReadError: If the tarfile is invalid or corrupted.
        Exception: For other unexpected errors during extraction.
    """
    try:
        # Check if the archive file exists
        if not os.path.exists(archive_path):
            raise FileNotFoundError(f"Archive file not found: {archive_path}")

        # Create the extraction directory if it doesn't exist
        if not os.path.exists(extract_path):
            try:
                os.makedirs(extract_path, exist_ok=True)  # exist_ok avoids errors if directory already exists
            except OSError as e:
                raise OSError(f"Failed to create extraction directory: {extract_path}. Error: {e}")

        # Open the tarfile
        try:
            with tarfile.open(archive_path, 'r') as tar:
                for member in tar.getmembers():
                    # Sanitize the filename to prevent path traversal
                    if not is_safe_path(extract_path, member.name):
                        print(f"Warning: Skipping potentially unsafe path: {member.name}")
                        continue  # Skip unsafe files

                    try:
                        tar.extract(member, path=extract_path)
                    except Exception as e:
                        print(f"Error extracting {member.name}: {e}")
                        # Decide whether to continue or abort based on the severity of the error
                        # For critical errors, you might want to re-raise the exception
                        # raise  # Uncomment to abort on extraction errors
                        pass # Continue to the next file

        except tarfile.ReadError as e:
            raise tarfile.ReadError(f"Error reading tarfile: {archive_path}.  Possible corruption or invalid format. Error: {e}")
        except Exception as e:
            raise Exception(f"An unexpected error occurred during extraction: {e}")

    except FileNotFoundError as e:
        print(f"Error: {e}")
        raise
    except OSError as e:
        print(f"Error: {e}")
        raise
    except tarfile.ReadError as e:
        print(f"Error: {e}")
        raise
    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == '__main__':
    archive_file = 'archive.zip'  # Replace with the actual path to your archive file
    extraction_directory = '/tmp/unpack'

    # Create a dummy archive.zip for testing with a potentially malicious path
    if not os.path.exists(archive_file):
        try:
            os.makedirs("dummy_files", exist_ok=True)
            with open("dummy_files/file1.txt", "w") as f:
                f.write("This is file 1.")
            with open("dummy_files/file2.txt", "w") as f:
                f.write("This is file 2.")
            
            # Create a tar.gz archive with a malicious path
            with tarfile.open(archive_file, "w:gz") as tar:
                tar.add("dummy_files/file1.txt", arcname="file1.txt")
                tar.add("dummy_files/file2.txt", arcname="../evil_file.txt")  # Malicious path

            # Clean up the dummy files directory
            shutil.rmtree("dummy_files")

        except Exception as e:
            print(f"Error creating dummy archive: {e}")
            exit(1)


    try:
        extract_tarfile_safe(archive_file, extraction_directory)
        print(f"Successfully extracted '{archive_file}' to '{extraction_directory}'")
    except (FileNotFoundError, OSError, tarfile.ReadError, Exception) as e:
        print(f"Extraction failed: {e}")

