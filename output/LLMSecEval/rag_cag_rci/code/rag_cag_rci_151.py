import os

    def is_safe_filename(filename):
        """
        Checks if a filename is safe to use.  Avoids relative paths, absolute paths,
        and potentially problematic characters.
        """
        if not filename:
            return False
        if os.path.isabs(filename):
            return False
        if ".." in filename:  # Prevent directory traversal
            return False
        # Add more checks for potentially dangerous characters as needed
        if any(c in filename for c in ["/", "\\", ":", "*", "?", "<", ">", "|"]):
            return False
        return True

    # Example usage:
    filename = user_provided_filename
    if is_safe_filename(filename):
        filepath = os.path.join(chroot_dir, "some_directory", filename)  # Still sanitize 'some_directory'
        # ... proceed with using filepath ...
    else:
        print("Error: Invalid filename.")

