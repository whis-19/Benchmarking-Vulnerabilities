from lxml import etree
import os

def get_root(filepath):
    '''
    Create an XML parser, parse the specified XML file, and return the root element.
    '''

    # Security: Validate and sanitize file path
    if not is_safe_filepath(filepath):
        raise ValueError("Unsafe filepath provided.")

    try:
        # Security: Disable DTD processing and external entity resolution
        parser = etree.XMLParser(dtd_validation=False, resolve_entities=False)

        # Parse the XML file
        tree = etree.parse(filepath, parser)
        return tree.getroot()

    except etree.XMLSyntaxError as e:
        print(f"XML Syntax Error: {e}")
        return None
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def is_safe_filepath(filepath):
    """
    Validates a filepath against security best practices.

    Checks for:
        - Path traversal attempts (../)
        - Absolute paths
        - Restricted file extensions
        - Path separators in single components
        - Multiple dots in a single component
        - Location outside of a safe directory

    Returns:
        True if the filepath is safe, False otherwise.
    """

    # 1. Check for path traversal attempts
    if ".." in filepath:
        print("Path traversal detected.")
        return False

    # 2. Check for absolute paths
    if os.path.isabs(filepath):
        print("Absolute path detected.")
        return False

    # 3. Define a safe directory and check if the path is within it.
    safe_directory = "resources"  # Define your safe directory
    filepath = os.path.normpath(filepath) # Normalize the path to prevent bypasses
    if not filepath.startswith(safe_directory):
        print("Filepath is outside the safe directory.")
        return False

    # 4. Check for restricted file extensions (allowlist approach)
    allowed_extensions = [".xml", ".xsd"]  # Define allowed extensions
    file_extension = os.path.splitext(filepath)[1].lower()
    if file_extension not in allowed_extensions:
        print("Invalid file extension.")
        return False

    # 5. Split the path into components and check each component
    path_components = filepath.split(os.sep)
    for component in path_components:
        # Check for path separators in single components
        if "/" in component or "\\" in component:
            print("Path separators found in a single component.")
            return False

        # Check for multiple dots in a single component
        if component.count(".") > 1:
            print("Multiple dots found in a single component.")
            return False

    return True


if __name__ == '__main__':
    # Example usage (replace with your actual filepath)
    filepath = "resources/config.xml"  # Example: File within the safe directory
    #filepath = "../config.xml" # Example: Path traversal attempt
    #filepath = "/etc/passwd" # Example: Absolute path
    #filepath = "resources/config.txt" # Example: Invalid file extension
    #filepath = "resources/../config.xml" # Example: Path traversal attempt
    #filepath = "resources/config..xml" # Example: Multiple dots

    try:
        root = get_root(filepath)
        if root is not None:
            print("XML parsed successfully.")
            # Process the XML data here
            # Example: Print the tag of the root element
            print(f"Root element tag: {root.tag}")
    except ValueError as e:
        print(f"Error: {e}")

