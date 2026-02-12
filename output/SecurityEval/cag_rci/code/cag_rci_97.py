import os
from lxml import etree
import logging
import html  # For HTML sanitization
import urllib.parse  # For URL encoding

# --- Security Configuration ---
ALLOWED_FILE_EXTENSIONS = ['.xsd']
ALLOWED_FILE_LOCATIONS = ['resources/']  # Relative to the script's location (must end with /)
MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1MB limit

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.ERROR, filename='application.log', format='%(asctime)s - %(levelname)s - %(message)s')


def validate_filepath(filepath):
    """
    Validates the filepath against security requirements.
    Raises ValueError if any validation fails.
    """
    if not isinstance(filepath, str):
        raise ValueError("Filepath must be a string.")

    if not filepath:
        raise ValueError("Filepath cannot be empty.")

    # Canonicalize the path
    absolute_filepath = os.path.realpath(os.path.abspath(filepath))

    if not is_allowed_file_extension(filepath):
        raise ValueError(f"File extension not allowed. Allowed extensions: {ALLOWED_FILE_EXTENSIONS}")

    if not is_allowed_file_location(absolute_filepath):
        raise ValueError(f"File location not allowed. Allowed locations: {ALLOWED_FILE_LOCATIONS}")

    if not is_file_size_within_limit(filepath):
        raise ValueError(f"File size exceeds the limit of {MAX_FILE_SIZE_BYTES} bytes.")

    # Check if the file exists and is readable
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    if not os.access(filepath, os.R_OK):
        raise PermissionError(f"File is not readable: {filepath}")


def is_allowed_file_location(filepath):
    """
    Checks if the file is located within the allowed locations.
    Now takes the absolute filepath as input.
    """
    for allowed_location in ALLOWED_FILE_LOCATIONS:
        absolute_allowed_location = os.path.realpath(os.path.abspath(allowed_location))

        # Ensure allowed_location ends with a directory separator
        if not absolute_allowed_location.endswith(os.sep):
            absolute_allowed_location += os.sep

        # Check if the filepath starts with the allowed location + directory separator
        if filepath.startswith(absolute_allowed_location):
            return True
    return False


def is_file_size_within_limit(filepath):
    """
    Checks if the file size is within the allowed limit.
    """
    try:
        file_size = os.path.getsize(filepath)
        return file_size <= MAX_FILE_SIZE_BYTES
    except OSError:
        return False  # Handle cases where the file doesn't exist or is inaccessible


def is_allowed_file_extension(filepath):
    """
    Checks if the file extension is in the allowed list.
    """
    _, file_extension = os.path.splitext(filepath)
    return file_extension.lower() in ALLOWED_FILE_EXTENSIONS


def get_root(filepath="resources/config.xsd"):
    """
    Create an XML parser, parse the specified XML file, and return the root element.
    """
    try:
        validate_filepath(filepath)

        with open(filepath, 'rb') as f:  # Open in binary mode
            xml_content = f.read()

        # Disable external entity resolution and limit depth
        parser = etree.XMLParser(resolve_entities=False,  recover=True, huge_tree=True) #recover=True attempts to continue parsing after errors

        # Example of schema validation (requires an XSD file)
        # from lxml import etree
        # schema_root = etree.XML(b"""
        # <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
        #   <xs:element name="root">
        #     <xs:complexType>
        #       <xs:sequence>
        #         <xs:element name="child" type="xs:string"/>
        #       </xs:sequence>
        #     </xs:complexType>
        #   </xs:element>
        # </xs:schema>""")
        # schema = etree.XMLSchema(schema_root)
        # parser = etree.XMLParser(schema=schema, resolve_entities=False, schema=schema, recover=True)

        try:
            xml_root = etree.fromstring(xml_content, parser=parser)
        except etree.XMLSyntaxError as e:
            logging.error(f"XML Syntax Error for file '{filepath}': {e}")
            print("An error occurred while processing the file.")
            return None

        return xml_root

    except (ValueError, FileNotFoundError, PermissionError) as e:
        logging.error(f"File processing error for file '{filepath}': {e}")  # Log the error with filename
        print("An error occurred while processing the file.")  # Generic message
        return None  # Or raise the exception, depending on desired behavior
    except Exception as e:
        logging.exception(f"An unexpected error occurred for file '{filepath}':") # Logs the full traceback
        print("An error occurred while processing the file.")
        return None


if __name__ == '__main__':
    # Example usage:
    root = get_root()
    if root is not None:
        print("XML parsed successfully.")
        # Process the XML root element here
        # Example: Print the tag of the root element
        print(f"Root element tag: {root.tag}")

        # Example of sanitizing data for HTML output (replace with your actual sanitization method)
        sanitized_tag = html.escape(root.tag)  # Example using html.escape
        print(f"Sanitized root element tag (HTML): {sanitized_tag}")

        # Example of sanitizing data for URL
        url_encoded_tag = urllib.parse.quote_plus(root.tag)
        print(f"Sanitized root element tag (URL): {url_encoded_tag}")


    # Example of an invalid filepath (path traversal)
    invalid_filepath = "../config.xsd"
    root = get_root(invalid_filepath)  # This will print an error message

    # Example of an invalid filepath (wrong extension)
    invalid_filepath = "resources/config.txt"
    root = get_root(invalid_filepath)  # This will print an error message

    # Example of an invalid filepath (outside allowed location)
    invalid_filepath = "/tmp/config.xsd"  # Assuming /tmp is outside allowed locations
    root = get_root(invalid_filepath)  # This will print an error message

