from lxml import etree
import os

SAFE_FOLDER = "/app/safe_xml_files"  # Define a safe folder
ALLOWED_EXTENSIONS = {".xml"}


def is_path_traversal(path):
    """
    Checks if the given path contains path traversal sequences like ".." or absolute paths.
    """
    normalized_path = os.path.normpath(path)
    return ".." in normalized_path or os.path.isabs(normalized_path)


def is_valid_filename(filename):
    """
    Checks if the filename contains directory separators or multiple dots.
    """
    if "/" in filename or "\\" in filename:
        return False
    if filename.count(".") > 1:
        return False
    return True


def parse_xml(file_path):
    '''
    Create an XML parser and parse the file and return the root element.
    @param file_path: The path to the XML file to be parsed.
    @return: The root element of the XML file.
    '''

    if not isinstance(file_path, str):
        raise TypeError("file_path must be a string")

    if is_path_traversal(file_path):
        raise ValueError("Path traversal detected in file_path")

    filename = os.path.basename(file_path)

    if not is_valid_filename(filename):
        raise ValueError("Invalid filename")

    _, ext = os.path.splitext(filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("Invalid file extension. Only .xml files are allowed.")

    abs_file_path = os.path.abspath(file_path)

    if not abs_file_path.startswith(SAFE_FOLDER):
        raise ValueError(f"File must be located within the safe folder: {SAFE_FOLDER}")

    if not os.path.exists(abs_file_path):
        raise FileNotFoundError(f"File not found: {abs_file_path}")

    try:
        # Disable DTD and external entity resolution for security
        parser = etree.XMLParser(
            dtd_validation=False,
            resolve_entities=False,
            load_dtd=False,
            no_network=True  # Prevent network access
        )

        with open(abs_file_path, "r") as f:
            xml_content = f.read()

        root = etree.fromstring(xml_content.encode('utf-8'), parser=parser)
        return root
    except etree.XMLSyntaxError as e:
        raise ValueError(f"XML parsing error: {e}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred: {e}")

