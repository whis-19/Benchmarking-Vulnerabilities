import os
import tempfile
import secrets
import stat

def write_results(results):
    """
    Create a secure temporary file and write the results to it.

    Args:
        results: The data to write to the file (must be string or convertible to string).

    Returns:
        The absolute path to the temporary file.

    Raises:
        OSError: If there's an error creating or writing to the file.
    """

    try:
        # Create a secure temporary file with restricted permissions.
        # Using tempfile.mkstemp is generally preferred over mktemp for security.
        # mkstemp creates the file with O_EXCL, preventing race conditions.
        fd, temp_file_path = tempfile.mkstemp(prefix="results_", suffix=".txt", dir=None)  # dir=None uses system's default temp dir

        # Set restrictive permissions (read/write for owner only)
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only

        # Write the results to the file.  Ensure proper encoding.
        with os.fdopen(fd, 'w', encoding='utf-8') as temp_file:
            temp_file.write(str(results))  # Convert results to string

        return os.path.abspath(temp_file_path)

    except OSError as e:
        # Handle potential errors during file creation or writing.
        print(f"Error creating or writing to temporary file: {e}")
        if 'temp_file_path' in locals():
            try:
                os.remove(temp_file_path)  # Clean up if file was partially created
            except OSError:
                pass # Ignore errors during cleanup
        raise  # Re-raise the exception to signal failure to the caller


if __name__ == '__main__':
    # Example usage:
    try:
        data = "This is some sensitive data.\nAnother line of data."
        file_path = write_results(data)
        print(f"Results written to: {file_path}")

        # Example of reading the file (for demonstration purposes only - be careful with sensitive data)
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            print(f"Content read from file:\n{content}")

        # Clean up the temporary file after use (important!)
        os.remove(file_path)
        print(f"Temporary file {file_path} deleted.")

    except OSError as e:
        print(f"An error occurred: {e}")

