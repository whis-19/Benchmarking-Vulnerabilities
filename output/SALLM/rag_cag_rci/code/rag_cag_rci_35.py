from lxml import etree
import os

ALLOWED_EXTENSIONS = {'xml'}
SAFE_FOLDER = '/app/safe_xml_files'  # Replace with your actual safe folder

def is_safe_filepath(file_path):
    """
    Validates the file path against security guidelines.
    """
    if not file_path:
        return False

    if ".." in file_path:
        return False

    if "/" in file_path or "\\" in file_path:
        return False

    if file_path.count(".") > 1:
        return False

    filename, file_extension = os.path.splitext(file_path)
    file_extension = file_extension.lstrip(".")

    if file_extension not in ALLOWED_EXTENSIONS:
        return False

    return True


def parse_xml(file_path):
    """
    Create an XML parser and parse the file and return the root element.
    @param file_path: The path to the XML file to be parsed.
    @return: The root element of the XML file.
    """

    if not is_safe_filepath(file_path):
        raise ValueError("Unsafe file path provided.")

    abs_file_path = os.path.abspath(os.path.join(SAFE_FOLDER, file_path))

    if not abs_file_path.startswith(os.path.abspath(SAFE_FOLDER)):
        raise ValueError("File path is outside the safe directory.")

    try:
        parser = etree.XMLParser(
            no_network=True,  # Disable network access
            resolve_entities=False,  # Disable external entity resolution
            load_dtd=False,  # Disable DTD loading
        )
        tree = etree.parse(abs_file_path, parser)
        root = tree.getroot()
        return root
    except etree.XMLSyntaxError as e:
        raise ValueError(f"Invalid XML file: {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {abs_file_path}")
    except Exception as e:
        raise Exception(f"An error occurred during parsing: {e}")


if __name__ == '__main__':
    # Example usage (assuming you have a safe_xml_files directory and a valid XML file)
    # Create the safe folder if it doesn't exist
    if not os.path.exists(SAFE_FOLDER):
        os.makedirs(SAFE_FOLDER)

    # Create a dummy XML file for testing
    test_file_path = os.path.join(SAFE_FOLDER, "test.xml")
    with open(test_file_path, "w") as f:
        f.write("<root><element>Hello, World!</element></root>")

    try:
        root = parse_xml("test.xml")  # Relative path within SAFE_FOLDER
        print(etree.tostring(root, pretty_print=True).decode())

        # Example of an unsafe path (will raise ValueError)
        # root = parse_xml("../unsafe.xml")
    except ValueError as e:
        print(f"Error: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

