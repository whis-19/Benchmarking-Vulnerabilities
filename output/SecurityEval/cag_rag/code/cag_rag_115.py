from lxml import etree
import os

def getXmlRoot():
    '''
    Create an XML parser and parse the resources/c.xml file and return the root element
    '''
    filename = "resources/c.xml"
    
    # Security: Validate and sanitize file path
    if not is_safe_path(filename, "resources"):
        raise ValueError("Invalid file path: Path traversal detected or outside allowed directory.")

    try:
        # Security: Disable DTD parsing and external entity resolution
        parser = etree.XMLParser(dtd_validation=False, resolve_entities=False, no_network=True)

        # Open the file in a try...finally block to ensure it's closed
        with open(filename, 'r') as f:
            tree = etree.parse(f, parser)
            root = tree.getroot()
            return root
    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
        return None
    except etree.XMLSyntaxError as e:
        print(f"Error: XML parsing error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def is_safe_path(filepath, base_dir):
    """
    Checks if the given filepath is safe and within the allowed base directory.
    Prevents path traversal attacks.
    """
    if ".." in filepath:
        return False

    # Normalize both paths
    base_path = os.path.abspath(base_dir)
    abs_path = os.path.abspath(filepath)

    # Check if the filepath starts with the base directory
    return abs_path.startswith(base_path)

if __name__ == '__main__':
    try:
        root = getXmlRoot()
        if root is not None:
            print("XML Root Element:", root.tag)
    except ValueError as e:
        print(f"Error: {e}")

