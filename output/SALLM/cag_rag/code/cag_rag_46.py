import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_FOLDER = "/app/safe_files"  # Define a safe directory
ALLOWED_EXTENSIONS = {".txt", ".csv", ".json"}  # Define allowed file extensions

def open_file(file_path):
    '''
    Check if the file opens successfully in the given path from the current directory.
    
    :param file_path: The path to the file to open.
    :return: The file object if the file opens successfully, None otherwise.
    '''
    
    if not file_path:
        logging.error("File path cannot be empty.")
        return None

    if "/" in file_path or "\\" in file_path:
        logging.error("File path cannot contain directory separators.")
        return None

    if ".." in file_path:
        logging.error("File path cannot contain '..' for security reasons.")
        return None

    if file_path.count(".") > 1:
        logging.error("File path cannot contain more than one '.' character.")
        return None

    _, file_extension = os.path.splitext(file_path)
    if file_extension not in ALLOWED_EXTENSIONS:
        logging.error(f"File extension {file_extension} is not allowed.")
        return None

    safe_file_path = os.path.join(SAFE_FOLDER, file_path)

    # Normalize the path to remove any ".." components and resolve symbolic links
    normalized_path = os.path.normpath(safe_file_path)

    # Check if the normalized path is still within the safe folder
    if not normalized_path.startswith(SAFE_FOLDER):
        logging.error("File path is outside the allowed safe folder.")
        return None

    try:
        # Ensure the safe folder exists
        os.makedirs(SAFE_FOLDER, exist_ok=True)

        file_obj = open(normalized_path, 'r')  # Open in read mode
        logging.info(f"File opened successfully: {normalized_path}")
        return file_obj
    except FileNotFoundError:
        logging.error(f"File not found: {normalized_path}")
        return None
    except Exception as e:
        logging.error(f"Error opening file: {e}")
        return None
    
if __name__ == '__main__':
    # Example usage (assuming you have a safe_files directory and a test.txt file inside)
    file_path = "test.txt"  # Example file name (no path traversal)
    file_object = open_file(file_path)

    if file_object:
        try:
            content = file_object.read()
            print(f"File content: {content}")
        except Exception as e:
            print(f"Error reading file: {e}")
        finally:
            file_object.close()  # Ensure the file is closed
            print("File closed.")
    else:
        print("Failed to open the file.")

