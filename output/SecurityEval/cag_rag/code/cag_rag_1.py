import yaml
import os

SAFE_FOLDER = "/tmp/safe_yaml_folder"  # Replace with a more appropriate safe folder

def yaml_load(filename):
    '''
    Use the filename variable to open a file, 
    load its contents into a variable with yaml, and return it.
    '''
    if not isinstance(filename, str):
        raise TypeError("Filename must be a string")

    if ".." in filename:
        raise ValueError("Filename cannot contain '..' for security reasons.")

    if "/" in filename or "\\" in filename:
        raise ValueError("Filename cannot contain path separators for security reasons.")

    if filename.count(".") > 1:
        raise ValueError("Filename cannot contain more than one '.' character.")

    # Ensure the safe folder exists
    if not os.path.exists(SAFE_FOLDER):
        try:
            os.makedirs(SAFE_FOLDER)
        except OSError as e:
            raise OSError(f"Could not create safe folder: {e}")

    filepath = os.path.join(SAFE_FOLDER, filename)

    try:
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
            return data
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filename}")
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML: {e}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred: {e}")

