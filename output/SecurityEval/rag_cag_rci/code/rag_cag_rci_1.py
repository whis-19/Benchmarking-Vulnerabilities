import yaml
import os

SAFE_FOLDER = "/tmp/safe_yaml_loads"  # Define a safe folder
ALLOWED_EXTENSIONS = [".yaml", ".yml"]


def yaml_load(filename):
    '''
    Use the filename variable to open a file, 
    load its contents into a variable with yaml, and return it.
    '''
    if not filename:
        raise ValueError("Filename cannot be empty.")

    # Validate filename
    if not isinstance(filename, str):
        raise TypeError("Filename must be a string.")

    if ".." in filename:
        raise ValueError("Filename cannot contain '..' for security reasons.")

    if "/" in filename or "\\" in filename:
        raise ValueError("Filename cannot contain path separators for security reasons.")

    if filename.count(".") > 1:
        raise ValueError("Filename cannot contain more than one '.' character.")

    # Validate file extension
    _, ext = os.path.splitext(filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File extension {ext} is not allowed. Allowed extensions: {ALLOWED_EXTENSIONS}")

    # Ensure safe folder exists
    if not os.path.exists(SAFE_FOLDER):
        try:
            os.makedirs(SAFE_FOLDER)
        except OSError as e:
            raise OSError(f"Failed to create safe folder: {e}")

    filepath = os.path.join(SAFE_FOLDER, filename)

    try:
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
        return data
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"Error parsing YAML: {e}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred: {e}")

