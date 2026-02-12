import os
import tarfile
import logging
import shutil
import resource  # For resource limits
import tempfile
import magic  # For file type detection

# ... (rest of your code)

def onerror(func, path, exc_info):
    """Error handler for shutil.rmtree."""
    logging.error(f"Error deleting {path}: {exc_info}")
    raise  # Re-raise the exception


def extract_tarfile_safely(tar_path, extract_path):
    """
    Extracts a tarfile safely, preventing path traversal and zip bombs.
    Includes post-extraction path validation.
    """

    try:
        # Set resource limits (requires root privileges on some systems)
        try:
            # Limit the maximum CPU time to 10 seconds
            resource.setrlimit(resource.RLIMIT_CPU, (10, 10))

            # Limit the maximum memory usage to 100MB
            resource.setrlimit(resource.RLIMIT_AS, (100 * 1024 * 1024, 100 * 1024 * 1024))

            # Limit the maximum file size to 1GB
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024 * 1024, 1024 * 1024 * 1024))

        except resource.error as e:
            logging.warning(f"Failed to set resource limits: {e}.  This may require root privileges.")


        with tarfile.open(tar_path, 'r') as tar:
            total_size = 0
            for member in tar.getmembers():
                # Split the member name into components
                path_components = os.path.normpath(member.name).split(os.sep)
                sanitized_components = []
                for component in path_components:
                    sanitized_component = sanitize_filepath(component)
                    if component != sanitized_component:
                        logging.warning(f"Sanitized path component from {component} to {sanitized_component}")
                    sanitized_components.append(sanitized_component)

                # Reconstruct the sanitized member name
                sanitized_member_name = os.path.join(*sanitized_components)
                member.name = sanitized_member_name


                # Prevent path traversal
                extract_path_member = os.path.join(extract_path, member.name)
                if not is_path_safe(extract_path_member, extract_path):
                    logging.warning(f"Skipping potentially unsafe member: {member.name}")
                    continue

                # Check for zip bomb vulnerability (size limits)
                if member.isfile():
                    total_size += member.size
                    # Example compression ratio check (requires knowing compressed size)
                    # compression_ratio = member.size / member.size_in_tar  # Assuming member.size_in_tar is available
                    # if compression_ratio > MAX_COMPRESSION_RATIO:
                    #     logging.error(f"Possible zip bomb detected: Compression ratio {compression_ratio} exceeds {MAX_COMPRESSION_RATIO}. Aborting extraction.")
                    #     return False
                    if total_size > MAX_UNCOMPRESSED_SIZE:
                        logging.error("Possible zip bomb detected.  Aborting extraction.")
                        return False

                try:
                    tar.extract(member, extract_path)
                    extracted_path = os.path.join(extract_path, member.name)

                    # POST-EXTRACTION PATH VALIDATION (CRITICAL)
                    real_extracted_path = os.path.realpath(extracted_path)
                    if not is_path_safe(real_extracted_path, UNPACK_DIR):
                        logging.error(f"Path traversal detected after extraction: {real_extracted_path}")
                        # Attempt to remove the extracted file/directory
                        try:
                            shutil.rmtree(extracted_path, ignore_errors=False, onerror=onerror)
                        except OSError as e:
                            logging.error(f"Failed to remove malicious file/directory: {e}")
                        return False

                    set_permissions(extracted_path, is_directory=member.isdir())

                except Exception as e:
                    logging.error(f"Error extracting {member.name}: {e}")
                    return False

        logging.info(f"Successfully extracted {tar_path} to {extract_path}")
        return True

    except tarfile.ReadError as e:
        logging.error(f"Tarfile read error: {e}")
        return False
    except FileNotFoundError:
        logging.error(f"File not found: {tar_path}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False


def process_file(filepath):
    """
    Processes the given file, extracting it if it's a tar archive.
    """
    # Use libmagic to determine the file type
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(filepath)
        if "application/gzip" not in file_type and "application/x-tar" not in file_type:
            logging.error(f"File type {file_type} is not a tar archive.")
            return False
    except magic.MagicException as e:
        logging.error(f"Error determining file type: {e}")
        return False

    # Sanitize the filepath
    sanitized_filepath = sanitize_filepath(filepath)
    if sanitized_filepath != os.path.basename(filepath):
        logging.warning(f"Filepath sanitized from {filepath} to {sanitized_filepath}")
        filepath = os.path.join(os.path.dirname(filepath), sanitized_filepath) #Reconstruct the path

    # Check if the file exists
    if not os.path.exists(filepath):
        logging.error(f"File not found: {filepath}")
        return False

    # Extract the tarfile
    return extract_tarfile_safely(filepath, UNPACK_DIR)


# --- Example Usage ---
if __name__ == "__main__":
    # Example usage:
    tar_file_path = 'example.tar.gz'  # Replace with the actual path to your tarfile

    # Create a dummy tar.gz file for testing (replace with your actual file)
    if not os.path.exists(tar_file_path):
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                dummy_file_path = os.path.join(tmpdir, "dummy_file.txt")
                with open(dummy_file_path, "w") as f:
                    f.write("This is a dummy file.")

                with tarfile.open(tar_file_path, "w:gz") as tar:
                    tarinfo = tarfile.TarInfo("dummy_file.txt")
                    tarinfo.size = os.path.getsize(dummy_file_path)
                    with open(dummy_file_path, "rb") as f:
                        tar.addfile(tarinfo, f)

            logging.info(f"Created dummy tar file: {tar_file_path}")
        except Exception as e:
            logging.error(f"Failed to create dummy tar file: {e}")
            exit(1)


    if process_file(tar_file_path):
        logging.info("File processed successfully.")
    else:
        logging.error("File processing failed.")

