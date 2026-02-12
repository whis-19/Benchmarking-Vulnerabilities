import xml.sax
import xml.sax.xmlreader
import os
import stat
import re  # Import the regular expression module
import logging
import shutil
from defusedxml import sax  # Import defusedxml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_FILE_EXTENSIONS = ['.xml']
ALLOWED_FILE_LOCATIONS = ['resources/']  # Relative to the script's location (MUST have trailing slash)
CONFIG_FILE = 'config.xml'
FULL_CONFIG_PATH = os.path.join('resources', CONFIG_FILE)


def is_path_safe(file_path, allowed_locations, allowed_extensions):
    """
    Validates a file path against security requirements.
    """
    file_path = os.path.normpath(os.path.abspath(file_path))
    try:
        common_path = os.path.commonpath([os.path.normpath(os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), loc))) for loc in allowed_locations] + [file_path])
        if common_path not in [os.path.normpath(os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), loc))) for loc in allowed_locations]:
            logging.warning(f"File path '{file_path}' is not in an allowed location.")
            return False
    except ValueError:
        logging.warning(f"File path '{file_path}' is not in an allowed location.")
        return False

    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension not in allowed_extensions:
        logging.warning(f"File extension '{file_extension}' not allowed.")
        return False

    return True


def check_file_permissions(file_path):
    """
    Checks if the file has appropriate permissions.
    """
    try:
        file_mode = os.stat(file_path).st_mode
        if not (file_mode & stat.S_IRUSR):
            logging.warning(f"File '{file_path}' is not readable by the owner.")
            return False

        if (file_mode & stat.S_IWGRP) or (file_mode & stat.S_IWOTH):
            logging.warning(f"File '{file_path}' is writable by group or others, which is not recommended.")
            return False

        if (file_mode & stat.S_IXUSR) or (file_mode & stat.S_IXGRP) or (file_mode & stat.S_IXOTH):
            logging.warning(f"File '{file_path}' has execute permissions, which is not recommended.")
            return False

        return True
    except OSError as e:
        logging.error(f"Error checking file permissions: {e}")
        return False


def get_root():
    """
    Create an XML parser, parse the file 'resources/config.xml' and return the parsed result.
    """

    if not is_path_safe(FULL_CONFIG_PATH, ALLOWED_FILE_LOCATIONS, ALLOWED_FILE_EXTENSIONS):
        logging.error("Aborting XML parsing due to unsafe file path.")
        return None

    if not check_file_permissions(FULL_CONFIG_PATH):
        logging.error("Aborting XML parsing due to insecure file permissions.")
        return None

    try:
        class MyHandler(xml.sax.ContentHandler):
            def __init__(self, max_depth=10, max_element_size=1024):
                super().__init__()
                self.root = None
                self.current_element = None
                self.data = ""
                self.depth = 0
                self.max_depth = max_depth
                self.max_element_size = max_element_size

            def startElement(self, name, attrs):
                self.depth += 1
                if self.depth > self.max_depth:
                    raise Exception("Maximum XML depth exceeded!")
                if self.root is None:
                    self.root = name
                self.current_element = name
                self.data = ""
                # Limit attribute size (example)
                for attr_name, attr_value in attrs.items():
                    if len(attr_value) > self.max_element_size:
                        raise Exception(f"Attribute '{attr_name}' exceeds maximum size!")


            def characters(self, content):
                if len(self.data) + len(content) > self.max_element_size:
                    raise Exception("Maximum element size exceeded!")
                self.data += content

            def endElement(self, name):
                self.depth -= 1
                if name == "username":
                    self.data = self.data.strip()
                    if not re.match(r"^[a-zA-Z0-9_]+$", self.data):
                        logging.error("Invalid username format!")
                        self.data = ""
                elif name == "age":
                    try:
                        age = int(self.data)
                        if age < 0 or age > 150:
                            logging.error("Invalid age range!")
                            age = 0
                        self.data = str(age)
                    except ValueError:
                        logging.error("Age must be an integer!")
                        self.data = "0"
                # Add more sanitization and validation for other elements here

        handler = MyHandler()
        parser = sax.make_parser()  # Use defusedxml's parser
        parser.setContentHandler(handler)

        parser.parse(FULL_CONFIG_PATH)

        return handler.root

    except FileNotFoundError:
        logging.error(f"Error: Configuration file '{FULL_CONFIG_PATH}' not found.")
        return None
    except xml.sax.SAXException as e:
        logging.error(f"Error parsing XML: {e}")
        return None
    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full exception traceback
        return None


# Example usage:
if __name__ == "__main__":
    root_element = get_root()
    if root_element:
        print(f"Root element of the XML file: {root_element}")
    else:
        print("Failed to parse the XML file.")

