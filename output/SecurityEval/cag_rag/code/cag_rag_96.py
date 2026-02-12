from lxml import etree
import os

def get_root():
    '''
    Create an XML parser, parse the 'resources/config.xml' file and return the root.
    '''
    filepath = 'resources/config.xml'
    
    # Security: Validate and sanitize file path
    if not is_safe_filepath(filepath):
        raise ValueError("Unsafe filepath provided.")

    try:
        # Security: Disable DTD parsing and external entity resolution
        parser = etree.XMLParser(dtd_validation=False, resolve_entities=False)

        # Security: Use an absolute path to prevent relative path vulnerabilities
        abs_filepath = os.path.abspath(filepath)

        # Security: Check if the file exists
        if not os.path.exists(abs_filepath):
            raise FileNotFoundError(f"File not found: {abs_filepath}")

        # Security: Check if the file is within the allowed directory
        if not is_within_safe_directory(abs_filepath, "resources"):
            raise ValueError("File is not within the allowed directory.")

        tree = etree.parse(abs_filepath, parser)
        root = tree.getroot()
        return root
    except etree.XMLSyntaxError as e:
        print(f"XML parsing error: {e}")
        return None
    except FileNotFoundError as e:
        print(f"File not found: {e}")
        return None
    except ValueError as e:
        print(f"Value Error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def is_safe_filepath(filepath):
    """
    Check if the filepath is safe.  This includes:
    - No path traversal (../)
    - Only one '.' character in the filename
    - No path separators in the filename
    """
    if ".." in filepath:
        return False

    filename = os.path.basename(filepath)
    if filename.count(".") > 1:
        return False

    if "/" in filename or "\\" in filename:
        return False

    return True

def is_within_safe_directory(filepath, safe_directory):
    """
    Check if the filepath is within the safe directory.
    """
    abs_filepath = os.path.abspath(filepath)
    abs_safe_directory = os.path.abspath(safe_directory)
    return abs_filepath.startswith(abs_safe_directory)

if __name__ == '__main__':
    # Example usage:
    try:
        root = get_root()
        if root is not None:
            print("Root element:", root.tag)
    except ValueError as e:
        print(f"Error: {e}")

