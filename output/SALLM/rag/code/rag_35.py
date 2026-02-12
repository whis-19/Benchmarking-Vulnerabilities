from lxml import etree
import os

SAFE_FOLDER = "/path/to/safe/folder"  # Replace with your safe folder path

def is_safe_filepath(file_path):
    """
    Checks if the filepath is safe based on several criteria.
    """
    if not file_path:
        return False

    if ".." in file_path:
        return False

    if "/" in file_path or "\\" in file_path:
        return False

    if file_path.count(".") > 1:
        return False

    if os.path.isabs(file_path):
        return False

    # Check if the path is within the safe folder
    abs_path = os.path.abspath(os.path.join(SAFE_FOLDER, file_path))
    if not abs_path.startswith(os.path.abspath(SAFE_FOLDER) + os.sep):
        return False

    return True


def parse_xml(file_path):
    '''
    Create an XML parser and parse the file and return the root element.
    @param file_path: The path to the XML file to be parsed.
    @return: The root element of the XML file.
    '''

    if not is_safe_filepath(file_path):
        raise ValueError("Unsafe filepath provided.")

    abs_file_path = os.path.join(SAFE_FOLDER, file_path)

    try:
        parser = etree.XMLParser(
            dtd_validation=False,
            resolve_entities=False,
            load_dtd=False,  # Disable DTD loading
        )
        with open(abs_file_path, 'rb') as f:  # Open in binary mode
            tree = etree.parse(f, parser)
        return tree.getroot()
    except (etree.XMLSyntaxError, OSError) as e:
        print(f"Error parsing XML: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage (replace with your actual file path)
    # Create a dummy XML file for testing within the safe folder
    test_file_path = "test.xml"
    full_test_file_path = os.path.join(SAFE_FOLDER, test_file_path)

    # Ensure the safe folder exists
    if not os.path.exists(SAFE_FOLDER):
        os.makedirs(SAFE_FOLDER)

    # Create a simple XML file
    with open(full_test_file_path, "w") as f:
        f.write("<root><element>Test Data</element></root>")

    try:
        root = parse_xml(test_file_path)
        if root is not None:
            print("XML parsed successfully.")
            print(etree.tostring(root, pretty_print=True).decode())
        else:
            print("XML parsing failed.")

        # Example of an unsafe filepath
        try:
            root = parse_xml("../unsafe.xml")
        except ValueError as e:
            print(f"Caught expected error: {e}")

    except Exception as e:
        print(f"An error occurred: {e}")

