from lxml import etree
import os
import sys
import logging
import tempfile

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def parse_xml(file_path, allowed_directory="/tmp", max_file_size=1024 * 1024):  # 1MB limit
    '''
    Create an XML parser and parse the file and return the root element.
    @param file_path: The path to the XML file to be parsed.
    @param allowed_directory: The directory where XML files are allowed to be read from.
    @param max_file_size: Maximum allowed file size in bytes.
    @return: The root element of the XML file.
    '''
    try:
        # Validate file path
        abs_path = os.path.abspath(file_path)
        # Robust path traversal check
        if os.path.commonpath([allowed_directory, abs_path]) != allowed_directory:
            raise ValueError(f"File path '{file_path}' is not within the allowed directory '{allowed_directory}'.")

        # File size check
        file_size = os.path.getsize(file_path)
        if file_size > max_file_size:
            raise ValueError(f"File size ({file_size} bytes) exceeds the maximum allowed size ({max_file_size} bytes).")


        # Use a secure XML parser to prevent XML External Entity (XXE) attacks
        parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)  # Disable network access, entity resolution, and DTD processing

        # Parse the XML file
        tree = etree.parse(file_path, parser)
        root = tree.getroot()
        return root
    except etree.XMLSyntaxError as e:
        logging.error(f"Error parsing XML: {e}")
        return None  # Or raise the exception, depending on desired behavior
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except ValueError as e:
        logging.error(f"Invalid file path or size: {e}")
        return None
    except IOError as e:
        logging.error(f"IOError: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {type(e).__name__}: {e}")  # Log the full traceback
        return None


if __name__ == '__main__':
    # Example usage (create a dummy XML file for testing)
    xml_content = """
    <!DOCTYPE root [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <root>
        <element1>Value 1</element1>
        <element2>&xxe;</element2>
    </root>
    """

    # Create the allowed directory if it doesn't exist with restricted permissions
    # allowed_directory = "/tmp"  # Using /tmp for example, adjust as needed
    # os.makedirs(allowed_directory, exist_ok=True, mode=0o700)

    # Use a temporary directory for the example
    allowed_directory = tempfile.mkdtemp(prefix="xml_example_", dir="/tmp") # Ensure /tmp exists
    print(f"Using temporary directory: {allowed_directory}")


    file_path = os.path.join(allowed_directory, "test.xml")

    # Create the XML file with restricted permissions
    try:
        fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w") as f:
            f.write(xml_content)
    except OSError as e:
        print(f"Error creating file: {e}")
        sys.exit(1)


    root_element = parse_xml(file_path, allowed_directory)

    if root_element is not None:
        print("XML parsed successfully.")
        for child in root_element:
            print(f"Element: {child.tag}, Value: {child.text}")
    else:
        print("XML parsing failed.")

    # Clean up the temporary directory (optional, but good practice)
    # import shutil
    # shutil.rmtree(allowed_directory)

