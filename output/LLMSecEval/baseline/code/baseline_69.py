import tarfile
import os
import shutil

def extract_tarfile(archive_path, extract_path):
    """
    Safely extracts a tarfile to a specified directory.

    Args:
        archive_path (str): The path to the tarfile.
        extract_path (str): The directory to extract the contents to.

    Raises:
        FileNotFoundError: If the archive file does not exist.
        OSError: If there are issues creating the extraction directory.
        tarfile.ReadError: If the tarfile is invalid or corrupted.
        Exception: For any other unexpected errors during extraction.
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
                raise OSError(f"Error creating extraction directory: {e}")

        # Open the tarfile
        try:
            with tarfile.open(archive_path, 'r') as tar:
                # Extract all members to the specified directory
                # Using extractall with numeric_owner=False is crucial for security
                # It prevents potential privilege escalation vulnerabilities.
                tar.extractall(path=extract_path, numeric_owner=False)
        except tarfile.ReadError as e:
            raise tarfile.ReadError(f"Error reading tarfile: {e}")
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
    extract_directory = '/tmp/unpack'

    # Create a dummy archive.zip for testing
    # This part is only for demonstration and should be removed in a real application
    if not os.path.exists(archive_file):
        try:
            os.makedirs(extract_directory, exist_ok=True)
            with open(os.path.join(extract_directory, "test_file.txt"), "w") as f:
                f.write("This is a test file.")
            
            # Create a tar.gz archive
            with tarfile.open(archive_file, "w:gz") as tar:
                tar.add(extract_directory, arcname="unpack") # Add the directory to the archive
            
            # Clean up the temporary directory
            shutil.rmtree(extract_directory)
        except Exception as e:
            print(f"Error creating dummy archive: {e}")
            exit(1)


    try:
        extract_tarfile(archive_file, extract_directory)
        print(f"Successfully extracted '{archive_file}' to '{extract_directory}'")
    except (FileNotFoundError, OSError, tarfile.ReadError, Exception) as e:
        print(f"Extraction failed: {e}")

