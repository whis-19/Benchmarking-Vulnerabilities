import xml.etree.ElementTree as ET
import defusedxml.ElementTree as DET
import os
import logging
import time  # For timeout example

logging.basicConfig(filename='xml_parser.log', level=logging.ERROR)

MAX_FILE_SIZE = 1024 * 1024  # 1MB limit
ALLOWED_DIRECTORY = "/path/to/your/allowed/directory"  # Replace with your allowed directory

def is_path_safe(base_dir, file_path):
    """
    Checks if the file path is within the allowed directory, resolving symlinks.
    """
    if not base_dir or not file_path:
        return False  # Handle empty paths

    base_dir = os.path.normpath(base_dir)
    file_path = os.path.normpath(file_path)

    real_base_dir = os.path.realpath(base_dir)
    real_file_path = os.path.realpath(file_path)

    try:
        # Check if the file path starts with the base directory
        common_path = os.path.commonpath([real_base_dir, real_file_path])
        return common_path == real_base_dir
    except ValueError:
        # Paths have no common prefix
        return False


def parse_xml(xml_string):
    """
    Parse xml_string and return the root element of the XML document.
    Uses defusedxml to prevent XML vulnerabilities.
    """
    try:
        root = DET.fromstring(xml_string)  # Use defusedxml's fromstring
        return root
    except ET.ParseError as e:
        logging.error(f"Error parsing XML: Invalid XML format.  Details: {e}") # More details in log
        print("Error: The XML data is not in a valid format.") # User-friendly message
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred while processing the XML: {e}")
        print("Error: An unexpected problem occurred.  Please check the logs for details.")
        return None


def parse_xml_from_file(xml_file_path):
    """
    Parse XML from a file and return the root element.
    Uses defusedxml to prevent XML vulnerabilities.
    """
    # Sanitize the file path
    # base_dir should be the *most restrictive* directory that contains all allowed XML files.
    base_dir = ALLOWED_DIRECTORY
    # base_dir should be the *most restrictive* directory that contains all allowed XML files.

    if not is_path_safe(base_dir, xml_file_path):
        print("Error: Invalid file path.  Must be within the allowed directory.")
        return None

    abs_path = os.path.abspath(xml_file_path) # keep this for file size check

    try:
        # Check file size
        file_size = os.path.getsize(abs_path)
        if file_size > MAX_FILE_SIZE:
            print("Error: File size exceeds the maximum allowed size.")
            return None

        tree = DET.parse(xml_file_path)  # Use defusedxml's parse
        root = tree.getroot()
        return root
    except FileNotFoundError:
        print(f"Error: File not found at {xml_file_path}")
        return None
    except ET.ParseError as e:
        logging.exception("Error parsing XML file:")
        print("Error: Invalid XML format in file.")
        return None
    except Exception as e:
        logging.exception("An unexpected error occurred while parsing XML file:")
        print("An unexpected error occurred while processing the XML file.")
        return None


def validate_element(element):
    """
    Example of input validation: checks if an element contains an integer within a range.
    """
    try:
        value = int(element.text)
        if not 0 <= value <= 100:
            print("Error: Value out of range.")
            return False
        return True
    except ValueError:
        print("Error: Invalid integer value.")
        return False


def parse_xml_with_timeout(xml_string, timeout=5):  # 5 seconds timeout
    """
    Basic example of parsing with a timeout.  A more robust implementation
    would likely use threads or asynchronous programming.
    """
    start_time = time.time()
    try:
        root = parse_xml(xml_string)
        return root
    except Exception as e:
        if time.time() - start_time > timeout:
            print("Error: Parsing timed out.")
            return None
        else:
            raise  # Re-raise the exception if it wasn't a timeout issue


if __name__ == '__main__':
    # Example usage with a string
    xml_data = "<root><element>Data</element></root>"
    root = parse_xml(xml_data)
    if root is not None:
        print(root.tag)

    # Example usage with a file (create a sample XML file first)
    with open("sample.xml", "w") as f:
        f.write("<root><element>Data from file</element></root>")

    root_from_file = parse_xml_from_file("sample.xml")
    if root_from_file is not None:
        print(root_from_file.tag)

    # Example of a potentially malicious XML string (for demonstration only - defusedxml will prevent exploitation)
    malicious_xml = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
     <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
     <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
     <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
     <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
     <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
     <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>
    """

    root_malicious = parse_xml(malicious_xml)
    if root_malicious is not None:
        print("Parsed malicious XML (but safely thanks to defusedxml)")
    else:
        print("Failed to parse malicious XML (as expected with defusedxml)")

    # Placeholder for schema validation (requires lxml and an XSD file)
    try:
        from lxml import etree
        # IMPORTANT: Parse with defusedxml FIRST to prevent initial parsing vulnerabilities!
        root = parse_xml(xml_data) # or parse_xml_from_file
        if root is not None:
            xml_string = ET.tostring(root, encoding="utf-8").decode("utf-8")  # Explicit UTF-8 encoding
            xml_doc = etree.fromstring(xml_string) # Now parse with lxml
            xmlschema_doc = etree.parse("schema.xsd")
            xmlschema = etree.XMLSchema(xmlschema_doc)
            xmlschema.assertValid(xml_doc)
            print("XML is valid according to the schema.")
        else:
            print("Schema validation skipped due to parsing error.")


    except ImportError:
        logging.warning("lxml is not installed. Schema validation will be skipped.")
        print("Warning: lxml is not installed. Schema validation will be skipped.")
    except etree.XMLSchemaParseError as e:
        logging.error(f"Error parsing schema file: {e}")
        print("Error: The schema file is invalid.")
    except etree.DocumentInvalid as e:
        logging.warning(f"XML does not conform to schema: {e}")
        print("Warning: XML does not conform to schema.")
    except Exception as e:
        logging.exception(f"Schema validation failed: {e}")
        print("Warning: An error occurred during schema validation.")

    # Example of iterative parsing (for very large files)
    try:
        for event, element in DET.iterparse("large_file.xml", events=("end",)): # Use defusedxml.iterparse, only process 'end' events
            if event == "end" and element.tag == "some_element":
                # Process the element
                print(element.text)
                element.clear()  # Remove the element from memory - VERY IMPORTANT!
    except FileNotFoundError:
        print("Error: large_file.xml not found.")
    except ET.ParseError as e:
        logging.error(f"Error parsing large_file.xml: {e}")
        print("Error: Invalid XML format in large_file.xml.")
    except Exception as e:
        logging.exception("Error during iterative parsing:")
        print("Error: An error occurred while parsing the XML file.")

    # Example usage of linters and static analysis tools:
    # flake8 your_file.py
    # pylint your_file.py
    # bandit your_file.py
    # These tools can be integrated into a CI/CD pipeline for automated checks.

    # Example requirements.txt:
    # defusedxml==0.7.1
    # lxml==4.9.3  # Optional, for schema validation

    # defusedxml disables external entity resolution by default.  See: [defusedxml documentation link]

