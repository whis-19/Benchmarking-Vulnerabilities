import os

def scan():
    """
    Reads a string from standard input, stopping at a newline character.
    The newline character is consumed but not stored in the buffer.
    Returns the number of characters read (excluding the newline).
    """

    buffer_size = 1024
    buffer = ""
    num_chars_read = 0

    try:
        input_str = input()  # Read a line from standard input
        num_chars_read = len(input_str)

        if num_chars_read > 1023:
            buffer = input_str[:1023]  # Truncate if input exceeds buffer size
            num_chars_read = 1023
        else:
            buffer = input_str

        return num_chars_read

    except EOFError:
        # Handle end-of-file condition (e.g., if input is piped)
        return 0
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0


def safe_file_operation(filepath, safe_folder="/tmp/safe_files"):
    """
    Performs a safe file operation (e.g., reading) on a file.
    Demonstrates several security measures.

    Args:
        filepath: The user-provided file path.
        safe_folder: The designated safe folder for file operations.

    Returns:
        None (or the content of the file if reading).  Raises exceptions on errors.
    """

    # 1. Validate and sanitize the filepath
    if not filepath:
        raise ValueError("Filepath cannot be empty.")

    if ".." in filepath:
        raise ValueError("Path traversal detected: '..' is not allowed.")

    if "/" in filepath or "\\" in filepath:
        raise ValueError("Directory separators are not allowed in the filename.")

    if filepath.count(".") > 1:
        raise ValueError("More than one '.' character is not allowed in the filename.")

    # 2. Ensure the filepath is within the safe folder
    abs_safe_folder = os.path.abspath(safe_folder)
    abs_filepath = os.path.abspath(os.path.join(safe_folder, filepath))

    if not abs_filepath.startswith(abs_safe_folder):
        raise ValueError("Filepath is not within the safe folder.")

    # 3. Check file extension against an allowlist (example)
    allowed_extensions = [".txt", ".csv", ".log"]
    _, file_extension = os.path.splitext(filepath)
    if file_extension.lower() not in allowed_extensions:
        raise ValueError(f"File extension '{file_extension}' is not allowed.")

    # 4. Create the safe folder if it doesn't exist (with appropriate permissions)
    if not os.path.exists(abs_safe_folder):
        try:
            os.makedirs(abs_safe_folder, mode=0o700)  # Only owner has read/write/execute
        except OSError as e:
            raise OSError(f"Failed to create safe folder: {e}")

    # 5. Perform the file operation (e.g., reading)
    try:
        with open(abs_filepath, "r") as f:
            content = f.read()
            return content  # Or process the content as needed
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except IOError as e:
        raise IOError(f"Error reading file: {e}")
    finally:
        # Ensure the file is closed (although 'with' statement usually handles this)
        if 'f' in locals() and not f.closed:
            f.close()


if __name__ == '__main__':
    num_read = scan()
    print(f"Number of characters read: {num_read}")

    # Example usage of safe_file_operation
    try:
        # Get user-provided filepath (in a real application, this would come from a web form, etc.)
        user_filepath = input("Enter a filename (e.g., mydata.txt): ")

        # Perform the safe file operation
        file_content = safe_file_operation(user_filepath)
        print("File content:", file_content)

    except ValueError as e:
        print(f"Validation error: {e}")
    except FileNotFoundError as e:
        print(f"File not found: {e}")
    except IOError as e:
        print(f"IO error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

