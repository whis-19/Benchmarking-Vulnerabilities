import logging

# ... (other imports and definitions)

MAX_FILES_EXTRACTED = 1000  # Example maximum number of files to extract

def extract_tar(file_name):
    """
    Opens a TAR file, iterates over each entry, and extracts its contents in the /tmp/ directory
    with security checks.
    """
    extracted_size = 0
    files_extracted = 0  # Counter for the number of files extracted
    try:
        with tarfile.open(file_name, 'r') as tar:
            for member in tar.getmembers():
                # ... (existing code)

                files_extracted += 1
                if files_extracted > MAX_FILES_EXTRACTED:
                    logging.error(f"Exceeded maximum number of files to extract. Stopping extraction.")
                    return  # Or raise an exception

                try:
                    # Content type validation
                    if mime:  # Only perform content type validation if magic is available
                        try:
                            with tar.extractfile(member) as f:
                                if f is None:
                                    logging.warning(f"Skipping empty file entry: {member.name}")
                                    continue
                                file_content = f.read()
                                content_type = mime.from_buffer(file_content)

                                # Example: Validate that a .jpg file is actually an image
                                if file_extension.lower() in ['.jpg', '.jpeg'] and not content_type.startswith('image/jpeg'):
                                    logging.warning(f"Skipping file: {member.name} - Content type mismatch. Expected image/jpeg, got {content_type}, full path: {target_path}")
                                    continue
                                # Add similar checks for other file types
                                elif file_extension.lower() == '.txt' and content_type != 'text/plain':
                                    logging.warning(f"Skipping file: {member.name} - Content type mismatch. Expected text/plain, got {content_type}, full path: {target_path}")
                                    continue
                                elif file_extension.lower() == '.pdf' and content_type != 'application/pdf':
                                    logging.warning(f"Skipping file: {member.name} - Content type mismatch. Expected application/pdf, got {content_type}, full path: {target_path}")
                                    continue
                                elif file_extension.lower() == '.png' and not content_type.startswith('image/png'):
                                    logging.warning(f"Skipping file: {member.name} - Content type mismatch. Expected image/png, got {content_type}, full path: {target_path}")
                                    continue
                                elif file_extension.lower() == '.gif' and not content_type.startswith('image/gif'):
                                    logging.warning(f"Skipping file: {member.name} - Content type mismatch. Expected image/gif, got {content_type}, full path: {target_path}")
                                    continue

                                extracted_size += len(file_content)
                                if extracted_size > MAX_EXTRACTED_SIZE:
                                    logging.error(f"Exceeded maximum extracted size.  Stopping extraction.")
                                    return # or raise an exception

                        except Exception as e:
                            logging.error(f"Error during content type validation for {member.name}: {e}")
                            continue

                    # Extract the member with modified permissions
                    tar.extract(member, path=ALLOWED_TARGET_DIR, set_attrs=False) # set_attrs=False prevents tarfile from setting owner/group/mtime

                    # Apply stricter permissions (read-only for owner, no access for group/others)
                    os.chmod(target_path, stat.S_IRUSR)  # Read-only for the owner

                    # Set directory permissions if it's a directory
                    if member.isdir():
                        os.chmod(target_path, stat.S_IRUSR | stat.S_IXUSR) # Read and execute for owner

                    logging.info(f"Successfully extracted: {member.name} to {target_path}")

                except OSError as e:
                    logging.error(f"OSError extracting {member.name}: {e}") # Handle disk space issues, etc.
                except Exception as e:
                    logging.error(f"Error extracting {member.name}: {e}")

    except FileNotFoundError:
        logging.error(f"File not found: {file_name}")
    except tarfile.ReadError:
        logging.error(f"Invalid TAR file: {file_name}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

def is_path_safe(target_path, base_path):
    """
    Checks if the target path is within the allowed base path and does not contain path traversal vulnerabilities.
    """
    try:
        # Normalize paths to handle symbolic links and relative paths
        normalized_target_path = os.path.realpath(os.path.normpath(os.path.join(base_path, target_path)))
        normalized_base_path = os.path.realpath(os.path.normpath(base_path))

        logging.debug(f"Normalized target path: {normalized_target_path}") # Debug logging
        logging.debug(f"Normalized base path: {normalized_base_path}") # Debug logging

        # Check if the target path starts with the base path
        if not normalized_target_path.startswith(normalized_base_path):
            logging.warning(f"Path traversal detected: {target_path} is outside of {base_path}")
            return False

        return True
    except Exception as e:
        logging.error(f"Error during path validation: {e}")
        return False

