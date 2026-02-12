import os
import logging

# Configure logging (optional, but recommended for security-related events)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_DIRECTORY = "/safe/"  # Define the safe directory
ALLOWED_EXTENSIONS = {".txt", ".csv", ".json"}  # Define allowed file extensions

def read_file_safely(filename):
    """
    Reads a file from the /safe/ directory, ensuring security.

    Args:
        filename (str): The name of the file to read (without path).

    Returns:
        str: The content of the file, or None if an error occurred.
    """
    if not filename:
        logging.error("Filename cannot be empty.")
        return None

    if "/" in filename or "\\" in filename:
        logging.error("Filename cannot contain path separators.")
        return None

    if ".." in filename:
        logging.error("Filename cannot contain '..' for path traversal protection.")
        return None

    if filename.count(".") > 1:
        logging.error("Filename cannot contain more than one '.' character.")
        return None

    # Extract the file extension
    file_extension = os.path.splitext(filename)[1]

    if file_extension not in ALLOWED_EXTENSIONS:
        logging.error(f"File extension '{file_extension}' is not allowed.")
        return None

    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Normalize the path to prevent path traversal
    normalized_path = os.path.normpath(filepath)

    if not normalized_path.startswith(SAFE_DIRECTORY):
        logging.error("Filepath is outside the safe directory.")
        return None

    if ".." in normalized_path.replace(SAFE_DIRECTORY, ""):
        logging.error("Normalized path contains '..' for path traversal protection.")
        return None

    try:
        with open(filepath, "r") as file:
            content = file.read()
            return content
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except IOError as e:
        logging.error(f"Error reading file: {filepath} - {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

# Example usage (assuming you have a file named "data.txt" in /safe/)
if __name__ == "__main__":
    file_content = read_file_safely("data.txt")

    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file.")

    # Example of an invalid filename
    file_content = read_file_safely("../../../etc/passwd")
    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file.")

    file_content = read_file_safely("data.csv.txt")
    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file.")

