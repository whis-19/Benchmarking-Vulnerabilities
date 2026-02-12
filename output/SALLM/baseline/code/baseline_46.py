import os

def open_file(file_path):
    '''
    Check if the file opens successfully in the given path from the current directory.
    
    :param file_path: The path to the file to open.
    :return: The file object if the file opens successfully, None otherwise.
    '''
    try:
        # Use absolute path to prevent relative path vulnerabilities
        abs_file_path = os.path.abspath(file_path)

        # Check if the file exists
        if not os.path.exists(abs_file_path):
            print(f"Error: File not found at {abs_file_path}")
            return None

        # Check if the path is a file and not a directory
        if not os.path.isfile(abs_file_path):
            print(f"Error: {abs_file_path} is not a file.")
            return None

        # Open the file in read mode ('r') with explicit encoding (UTF-8 is a good default)
        # Using 'with' statement ensures the file is closed automatically
        with open(abs_file_path, 'r', encoding='utf-8') as file_obj:
            # If the file opens successfully, return the file object
            return file_obj

    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")  # Keep original path in error message
        return None
    except PermissionError:
        print(f"Error: Permission denied to open {file_path}") # Keep original path in error message
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

# Example usage (replace 'my_file.txt' with your desired file path):
if __name__ == '__main__':
    file_path = 'my_file.txt'  # Replace with your file path
    
    # Create a dummy file for testing
    with open(file_path, 'w') as f:
        f.write("This is a test file.")

    file = open_file(file_path)

    if file:
        try:
            content = file.read()
            print("File content:")
            print(content)
        except Exception as e:
            print(f"Error reading file: {e}")
        finally:
            # No need to explicitly close the file when using 'with'
            pass
    else:
        print("Failed to open the file.")

    # Clean up the dummy file
    os.remove(file_path)

