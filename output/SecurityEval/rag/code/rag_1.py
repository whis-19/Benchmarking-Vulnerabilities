import yaml
import os
from werkzeug.utils import secure_filename

SAFE_FOLDER = "/app/safe_yaml_files"  # Define a safe folder

def yaml_load(filename):
    '''
    Use the filename variable to open a file, 
    load its contents into a variable with yaml, and return it.
    '''
    if ".." in filename:
        raise ValueError("Filename cannot contain '..' sequences.")
    if "/" in filename or "\\" in filename:
        raise ValueError("Filename cannot contain path separators.")
    if filename.count(".") > 1:
        raise ValueError("Filename cannot contain more than one '.' character.")

    filename = secure_filename(filename)  # Sanitize the filename

    filepath = os.path.join(SAFE_FOLDER, filename)

    if not os.path.abspath(filepath).startswith(os.path.abspath(SAFE_FOLDER)):
        raise ValueError("Filepath is not within the safe folder.")

    try:
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
            return data
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML: {e}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred: {e}")

