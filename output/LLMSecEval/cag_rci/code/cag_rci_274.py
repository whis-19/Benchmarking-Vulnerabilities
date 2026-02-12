import os
import logging

def is_path_safe(filepath, allowed_locations):
    """
    Validates if a filepath is safe based on allowlists and path traversal checks,
    resolving symlinks.

    Args:
        filepath (str): The path to validate.
        allowed_locations (list): A list of allowed parent directories.

    Returns:
        bool: True if the path is safe, False otherwise.
    """
    try:
        filepath = os.path.realpath(filepath)  # Resolve symlinks
        filepath = os.path.abspath(os.path.normpath(filepath))  # Normalize and make absolute
    except OSError as e:
        logging.error(f"Error resolving path (possibly broken symlink): {e}")
        return False
    except RecursionError:
        logging.error("Symlink loop detected.")
        return False


    if ".." in filepath:
        logging.error("Path traversal detected.")
        return False

    try:
        # Check if the filepath starts with any of the allowed locations
        if not any(os.path.commonpath([loc, filepath]) == loc for loc in allowed_locations):
            logging.error(f"Filepath not in allowed locations: {allowed_locations}")
            return False
    except ValueError:
        # Handle cases where the paths have no common prefix
        logging.error("Paths have no common prefix.")
        return False

    return True

