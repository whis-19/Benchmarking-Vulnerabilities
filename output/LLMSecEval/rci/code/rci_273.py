import hashlib
import os
import pathlib  # Import pathlib
import re
import signal


def sanitize_path(path_string, base_dir):
    """Sanitizes a path to prevent path traversal."""
    path = pathlib.Path(path_string)

    # Reject absolute paths
    if path.is_absolute():
        raise ValueError("Absolute paths are not allowed.")

    # Reject paths containing ".."
    try:
        resolved_path = path.resolve(strict=True)  # strict=True raises FileNotFoundError if the file doesn't exist
    except FileNotFoundError:
        # Handle the case where the file doesn't exist yet.  This is important for output paths.
        pass
    else:
        if not str(resolved_path).startswith(str(pathlib.Path(base_dir).resolve())):
            raise ValueError("Path traversal detected: '..' component.")

    # Whitelist allowed characters in the filename
    filename = path.name
    if not re.match(r"^[a-zA-Z0-9_\-.]+$", filename):
        raise ValueError("Invalid characters in filename.")

    return path  # Return the original pathlib.Path object


def secure_file_processing(input_file_path, output_file_path, timeout=30, base_dir="."):
    """
    Reads a file, calculates its checksum, checks for emptiness,
    and saves the number of bytes read and the checksum to another file.

    Args:
        input_file_path (str): The path to the input file.
        output_file_path (str): The path to the output file where the results will be saved.
        timeout (int): Timeout in seconds for file processing.
        base_dir (str): Base directory for path sanitization.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """

    def timeout_handler(signum, frame):
        raise TimeoutError("File processing timed out.")

    try:
        # Set the timeout handler
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)  # Start the timer

        # Input validation: Check file paths
        if not isinstance(input_file_path, str) or not isinstance(output_file_path, str):
            raise TypeError("File paths must be strings.")

        # Use pathlib for safer path manipulation and path sanitization
        try:
            input_path = sanitize_path(input_file_path, base_dir)
            output_path = sanitize_path(output_file_path, base_dir)
        except ValueError as e:
            print(f"Invalid file path: {e}")
            return False

        # Input validation: Check if the input file exists
        if not input_path.is_file():
            raise FileNotFoundError(f"Input file not found: {input_file_path}")

        # Resource Limit: Maximum file size (e.g., 10MB)
        max_file_size = 10 * 1024 * 1024  # 10 MB
        file_size = input_path.stat().st_size
        if file_size > max_file_size:
            raise ValueError(f"Input file exceeds maximum allowed size ({max_file_size} bytes)")

        # Read the file in binary mode for accurate checksum calculation.
        try:
            with open(input_path, "rb") as f:
                buffer = f.read()
        except PermissionError as e:
            print(f"Error: Permission denied while reading file: {e}")
            return False
        except FileNotFoundError as e:
            print(f"Error: Input file not found: {e}")
            return False
        except IsADirectoryError as e:
            print(f"Error: Input path is a directory: {e}")
            return False
        except OSError as e:
            print(f"Error reading file: {e}")
            return False

        num_bytes_read = len(buffer)

        # Calculate the SHA-256 checksum for strong security.  Consider other algorithms if needed.
        hasher = hashlib.sha256()
        hasher.update(buffer)
        checksum = hasher.hexdigest()

        # Check if the buffer is empty based on its length.  Checksum of an empty file is not reliable.
        is_empty = num_bytes_read == 0

        # Prepare the data to be written to the output file.
        output_data = f"Bytes Read: {num_bytes_read}\nChecksum (SHA-256): {checksum}\nFile Empty: {is_empty}\n"

        # Securely write the data to the output file.  Use a temporary file and atomic rename to prevent data corruption.
        temp_output_file_path = str(output_path) + ".tmp"  # Create a temporary file name

        try:
            with open(temp_output_file_path, "w") as f:
                f.write(output_data)

            # Atomic rename to ensure data integrity.  This is crucial to prevent partial writes.
            os.replace(temp_output_file_path, str(output_path))
            # Note: The atomicity of os.replace can depend on the underlying operating system and file system.
            # For critical applications, verify atomicity on the target platform.

        except OSError as e:
            print(f"Error writing to output file: {e}")
            # Clean up the temporary file if it exists
            if os.path.exists(temp_output_file_path):
                try:
                    os.remove(temp_output_file_path)
                except OSError as remove_err:
                    print(f"Failed to remove temporary file: {remove_err}")
            return False

        # Checksum Verification: In a real-world scenario, you would typically store the checksum
        # separately and then verify it after reading the file to ensure that the file hasn't been tampered with.

        signal.alarm(0)  # Disable the timer if processing completes successfully
        return True

    except TimeoutError:
        print("Error: File processing timed out.")
        return False
    except (TypeError, FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        return False
    except Exception as e:
        # Ensure the alarm is cancelled even if other exceptions occur
        signal.alarm(0)
        print(f"An unexpected error occurred: {e}")
        return False
    finally:
        # Ensure the alarm is always cancelled
        signal.alarm(0)


# Example usage:
if __name__ == "__main__":
    # Create a dummy input file for testing
    input_file = "input.txt"
    output_file = "output.txt"
    base_dir = "."  # Current directory for example

    try:
        with open(input_file, "w") as f:
            f.write("This is a test file.\n")
    except OSError as e:
        print(f"Error creating test file: {e}")
        exit(1)

    if secure_file_processing(input_file, output_file, base_dir=base_dir):
        print(f"File processing successful. Results saved to {output_file}")
    else:
        print("File processing failed.")

    # Clean up the test file
    try:
        os.remove(input_file)
    except OSError as e:
        print(f"Error deleting test file: {e}")

