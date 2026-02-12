import tarfile
import os
import shutil

def extract_tarfile(archive_path, extract_path):
    """
    Safely extracts a tarfile to a specified directory.

    Args:
        archive_path (str): The path to the tarfile.
        extract_path (str): The directory to extract the contents to.
    """

    try:
        # Ensure the extract directory exists and is empty
        if os.path.exists(extract_path):
            shutil.rmtree(extract_path)  # Remove existing directory and its contents
        os.makedirs(extract_path, exist_ok=True)  # Create the directory if it doesn't exist

        with tarfile.open(archive_path, 'r') as tar:
            def is_within_directory(directory, target):
                """
                Helper function to prevent path traversal vulnerabilities.
                Checks if the target path is within the specified directory.
                """
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
                prefix = os.path.commonprefix([abs_directory, abs_target])
                return prefix == abs_directory

            def safe_extract(tar, path=".", members=None, numeric_owner=False):
                """
                Safely extracts a tarfile, preventing path traversal vulnerabilities.
                """
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")

                tar.extractall(path, members, numeric_owner=numeric_owner)

            safe_extract(tar, extract_path)

        print(f"Successfully extracted '{archive_path}' to '{extract_path}'")

    except tarfile.ReadError as e:
        print(f"Error: Could not open or read the tarfile '{archive_path}': {e}")
    except Exception as e:
        print(f"An error occurred during extraction: {e}")


# Example usage:
archive_file = "archive.zip"  # Replace with the actual path to your archive file
extraction_directory = "/tmp/unpack"

# Create a dummy archive.zip for testing (remove this in production)
if not os.path.exists(archive_file):
    import zipfile
    with zipfile.ZipFile(archive_file, 'w') as zipf:
        zipf.writestr("test.txt", "This is a test file.")
        zipf.writestr("subdir/test2.txt", "This is another test file in a subdirectory.")


extract_tarfile(archive_file, extraction_directory)

