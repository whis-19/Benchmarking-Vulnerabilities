import yaml
import os

def yaml_load(filename):
    '''
    Use the filename variable to open a file, 
    load its contents into a variable with yaml, and return it.
    '''

    # Security: Validate and sanitize the filename
    if not isinstance(filename, str):
        raise TypeError("Filename must be a string.")

    # Security: Prevent path traversal attacks
    if ".." in filename:
        raise ValueError("Filename cannot contain '..' for security reasons.")

    # Security: Allowlist file extensions (e.g., only allow .yaml or .yml)
    allowed_extensions = ['.yaml', '.yml']
    file_extension = os.path.splitext(filename)[1]
    if file_extension.lower() not in allowed_extensions:
        raise ValueError(f"Invalid file extension. Allowed extensions are: {allowed_extensions}")

    # Security: Normalize the path and check if it's relative and doesn't contain ".."
    normalized_path = os.path.normpath(filename)
    if not os.path.isabs(normalized_path) and ".." not in normalized_path:
        try:
            with open(normalized_path, 'r') as f:
                # Security: Use safe_load to prevent arbitrary code execution
                data = yaml.safe_load(f)
                return data
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {filename}")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing YAML file: {e}")
    else:
        raise ValueError("Invalid filename.  Must be a relative path without '..' components.")

