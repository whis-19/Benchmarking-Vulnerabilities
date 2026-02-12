import tarfile
import os
import logging
import shutil

# Configure logging
logging.basicConfig(level=logging.ERROR)


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
    abs_path = os.path.abspath(os.path.join(abs_basedir, os.path.normpath(path)))  # Normalize path before joining

    return abs_path.startswith(abs_basedir)


def extract_tarfile_safe(archive_file, extraction_directory):
    """
    Extracts a tarfile safely, preventing path traversal vulnerabilities.

    Args:
        archive_file (str): The path to the tarfile.
        extraction_directory (str): The directory to extract the contents to.
    """
    try:
        with tarfile.open(archive_file, "r:gz") as tar:
            for member in tar.getmembers():
                member_path = member.name  # Path inside the archive

                if not is_safe_path(extraction_directory, member_path):
                    logging.error(f"Unsafe path detected: {member_path}. Skipping extraction.")
                    continue  # Skip to the next member

                try:
                    tar.extract(member, extraction_directory)
                except Exception as e:
                    logging.error(f"Error extracting {member.name}: {e}")
                    # Decide whether to continue or abort based on the severity of the error
                    # raise  # Uncomment to abort on extraction errors
                    pass # Continue to the next file

    except FileNotFoundError as e:
        raise  # Re-raise to be handled in the main block
    except tarfile.ReadError as e:
        raise  # Re-raise to be handled in the main block
    except Exception as e:
        raise  # Re-raise to be handled in the main block


if __name__ == '__main__':
    archive_file = "archive.tar.gz"
    extraction_directory = "extracted_files"

    # Create a dummy archive.tar.gz for testing with a potentially malicious path
    if not os.path.exists(archive_file):
        try:
            os.makedirs("dummy_files", exist_ok=True)
            with open("dummy_files/file1.txt", "w") as f:
                f.write("This is file 1.")
            with open("dummy_files/file2.txt", "w") as f:
                f.write("This is file 2.")

            # Create a tar.gz archive with a malicious path
            # shutil.make_archive("archive", "gztar", root_dir=".", base_dir="dummy_files") # This won't allow setting arcname
            with tarfile.open(archive_file, "w:gz") as tar:
                tar.add("dummy_files/file1.txt", arcname="file1.txt")  # Add file1.txt to the archive with the name "file1.txt"
                tar.add("dummy_files/file2.txt", arcname="../evil_file.txt")  # Add file2.txt with a malicious path (arcname) to test path traversal prevention


            # Clean up the dummy files directory
            shutil.rmtree("dummy_files")

        except Exception as e:
            print(f"Error creating dummy archive: {e}")
            exit(1)

    # Extract the archive safely
    try:
        extract_tarfile_safe(archive_file, extraction_directory)
        print(f"Successfully extracted '{archive_file}' to '{extraction_directory}'")
    except FileNotFoundError as e:
        print(f"File not found: {e}")
    except OSError as e:
        print(f"OS error: {e}")
    except tarfile.ReadError as e:
        print(f"Tarfile read error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

