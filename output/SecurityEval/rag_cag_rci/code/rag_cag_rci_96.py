from lxml import etree
import os

def get_root(filepath):
    '''
    Create an XML parser, parse the specified XML file and return the root.
    '''

    # Security: Validate and sanitize the filepath
    if not is_safe_filepath(filepath):
        raise ValueError("Unsafe filepath provided.")

    try:
        # Security: Disable DTD processing and external entity resolution
        parser = etree.XMLParser(dtd_validation=False, resolve_entities=False)

        # Security: Use an absolute path to prevent relative path vulnerabilities
        abs_filepath = os.path.abspath(filepath)

        # Security: Check if the file exists
        if not os.path.exists(abs_filepath):
            raise FileNotFoundError(f"File not found: {abs_filepath}")

        # Security: Check if the file is within the allowed directory
        if not is_within_allowed_directory(abs_filepath, "resources"):
            raise ValueError("File is not within the allowed directory.")

        # Parse the XML file
        tree = etree.parse(abs_filepath, parser)
        root = tree.getroot()
        return root

    except etree.XMLSyntaxError as e:
        raise ValueError(f"XML parsing error: {e}")
    except FileNotFoundError as e:
        raise FileNotFoundError(f"File not found: {e}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred: {e}")


def is_safe_filepath(filepath):
    """
    Validates the filepath to prevent path traversal attacks.
    """
    # Check for empty filepath
    if not filepath:
        return False

    # Check for ".." sequences
    if ".." in filepath:
        return False

    # Check for absolute paths
    if os.path.isabs(filepath):
        return False

    # Check for multiple consecutive dots
    if "..." in filepath:
        return False

    # Check for path separators at the beginning or end
    if filepath.startswith(('/', '\\')) or filepath.endswith(('/', '\\')):
        return False

    # Check for invalid characters (example, adjust as needed)
    invalid_chars = ['<', '>', ';', '`', '|', '$', '&', '*', '?', '[', ']', '{', '}', '=', '+', '%']
    if any(char in filepath for char in invalid_chars):
        return False

    # Check for more than one dot in the filename component
    filename = os.path.basename(filepath)
    if filename.count('.') > 1:
        return False

    return True


def is_within_allowed_directory(filepath, allowed_directory):
    """
    Checks if the filepath is within the allowed directory.
    """
    abs_filepath = os.path.abspath(filepath)
    abs_allowed_directory = os.path.abspath(allowed_directory)
    return abs_filepath.startswith(abs_allowed_directory)


if __name__ == '__main__':
    try:
        # Example usage with a safe filepath
        root = get_root("resources/config.xml")  # Assuming config.xml exists in the resources directory
        print("Root tag:", root.tag)

        # Example usage with an unsafe filepath (will raise an exception)
        # root = get_root("../config.xml")  # This will raise a ValueError
    except ValueError as e:
        print(f"Error: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

