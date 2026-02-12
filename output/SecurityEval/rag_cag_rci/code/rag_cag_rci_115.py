from lxml import etree
import os

def getXmlRoot():
    '''
    Create an XML parser and parse the resources/c.xml file and return the root element
    '''
    filename = "resources/c.xml"
    safe_dir = "resources"  # Define a safe directory

    # Validate filename and prevent path traversal
    if not filename:
        raise ValueError("Filename cannot be empty.")

    if ".." in filename:
        raise ValueError("Path traversal detected in filename.")

    # Check for multiple dots
    if filename.count(".") > 1:
        raise ValueError("Invalid filename: Multiple dots detected.")

    # Check if the file is within the safe directory
    abs_path = os.path.abspath(filename)
    abs_safe_dir = os.path.abspath(safe_dir)

    if not abs_path.startswith(abs_safe_dir):
        raise ValueError("Filename is not within the safe directory.")

    # Validate file extension (allowlist approach)
    allowed_extensions = [".xml"]
    file_extension = os.path.splitext(filename)[1].lower()
    if file_extension not in allowed_extensions:
        raise ValueError(f"Invalid file extension: {file_extension}. Allowed extensions are: {allowed_extensions}")

    try:
        # Disable DTD processing and external entity resolution
        parser = etree.XMLParser(dtd_validation=False, resolve_entities=False)

        # Open and parse the XML file
        with open(filename, "r") as f:
            tree = etree.parse(f, parser)
            root = tree.getroot()
            return root
    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
        return None
    except etree.XMLSyntaxError as e:
        print(f"Error: XML syntax error in {filename}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

