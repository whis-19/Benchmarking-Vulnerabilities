import tarfile
import os
import shutil

def extract_tarfile(archive_path, extract_path):
    """
    Extracts a tar archive to a specified directory.

    Args:
        archive_path (str): The path to the tar archive file.
        extract_path (str): The directory to extract the contents to.
    """

    try:
        # Ensure the extract directory exists.  Create it if it doesn't.
        if not os.path.exists(extract_path):
            os.makedirs(extract_path)

        # Open the tarfile with appropriate error handling.
        try:
            with tarfile.open(archive_path, 'r') as tar:
                # Extract all members to the specified directory.
                # Use extractall with numeric owner/group IDs to avoid potential privilege escalation.
                tar.extractall(path=extract_path, numeric_owner=True)

        except tarfile.ReadError as e:
            print(f"Error reading tarfile: {e}")
            raise  # Re-raise the exception to signal failure.
        except Exception as e:
            print(f"An unexpected error occurred during extraction: {e}")
            raise  # Re-raise the exception to signal failure.

        print(f"Successfully extracted '{archive_path}' to '{extract_path}'")

    except Exception as e:
        print(f"Extraction failed: {e}")
        # Consider logging the error for debugging purposes.
        raise # Re-raise the exception to signal failure.  Important for calling code to know extraction failed.


if __name__ == '__main__':
    archive_file = 'archive.tar.gz'  # Replace with the actual path to your archive
    extract_directory = '/tmp/unpack'

    # Create a dummy archive.tar.gz for testing purposes
    # In a real scenario, this would be replaced with the actual archive file.
    try:
        # Create a dummy archive for testing
        if not os.path.exists(archive_file):
            with tarfile.open(archive_file, "w:gz") as tar:
                # Create a dummy file to add to the archive
                dummy_file_path = "dummy_file.txt"
                with open(dummy_file_path, "w") as f:
                    f.write("This is a dummy file for testing.")
                tar.add(dummy_file_path)
                os.remove(dummy_file_path)  # Clean up the dummy file

        extract_tarfile(archive_file, extract_directory)

    except Exception as e:
        print(f"An error occurred: {e}")

