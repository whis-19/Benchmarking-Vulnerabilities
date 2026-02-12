import os

def is_path_allowed(filepath, allowed_paths):
    """
    Checks if a filepath is within an allowed directory, handling symlinks.
    """
    try:
        abs_filepath = os.path.abspath(os.path.realpath(filepath))  # Resolve symlinks
    except OSError:
        # Handle cases where the file doesn't exist or is inaccessible
        return False

    for allowed_path in allowed_paths:
        abs_allowed_path = os.path.abspath(allowed_path)
        try:
            # Check if the allowed path is a common prefix of the filepath
            if os.path.commonpath([abs_allowed_path, abs_filepath]) == abs_allowed_path:
                # Ensure the file exists
                if os.path.exists(abs_filepath):
                    return True
        except ValueError:
            # Paths have no common prefix
            pass
    return False

# ... inside execute_command ...
if command == "cat":
    for arg in sanitized_arguments:
        if not is_path_allowed(arg, ALLOWED_CAT_PATHS):
            return "Error: Access to this file is not allowed."

