import os

def is_safe_path(basedir, path):
    """
    Checks if the given path is within the basedir to prevent path traversal.
    """
    try:
        abs_basedir = os.path.abspath(basedir)
        abs_path = os.path.abspath(os.path.join(basedir, path))

        # Canonicalize paths to handle symlinks and other tricks
        abs_basedir = os.path.realpath(abs_basedir)
        abs_path = os.path.realpath(abs_path)

        # WARNING: os.path.realpath() resolves symlinks.  This might be
        # undesirable in some cases.  If you need to prevent symlink traversal,
        # you will need to use a different approach to path validation.

        if not abs_path.startswith(abs_basedir):
            return False

        return True
    except OSError as e:  # Catch OSError for file system errors
        print(f"Error in is_safe_path: {e}")
        # Consider raising an exception if the error is critical
        # For example, if basedir doesn't exist, it's a configuration error
        if not os.path.exists(basedir):
            raise ValueError(f"Basedir '{basedir}' does not exist.") from e
        return False  # Or raise, depending on your error handling strategy
    except Exception as e:
        print(f"Unexpected error in is_safe_path: {e}")
        return False # Or raise an exception, depending on your error handling strategy

