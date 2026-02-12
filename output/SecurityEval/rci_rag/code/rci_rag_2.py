import defusedxml.ElementTree as ET
from defusedxml import defuse_stdlib
import logging
import re  # For data validation

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

defuse_stdlib()  # Apply defusedxml patches to the standard library

def parse_xml(xml_string):
    '''
    Parse xml_string and return the root element of the XML document.
    Uses defusedxml to prevent XML attacks.
    Returns the root element if parsing is successful, None otherwise.
    '''
    try:
        root = ET.fromstring(xml_string)
        return root
    except ET.ParseError as e:
        logging.error(f"XML Parsing Error: {e}")
        return None
    except Exception as e:
        logging.exception("An unexpected error occurred during XML parsing:")  # Log the full exception
        return None


if __name__ == '__main__':
    # Example usage with a potentially malicious XML string
    xml_string = """<?xml version="1.0"?>
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <foo>&xxe;</foo>
    """

    root = parse_xml(xml_string)

    if root is not None:
        logging.info("XML parsed successfully (or at least, without crashing).")

        # Example of safe data extraction (replace with your actual logic)
        element = root.find('foo')
        if element is not None:
            element_text = element.text
            logging.info(f"Extracted text from 'foo' element: {element_text}")
        else:
            logging.warning("Element 'foo' not found.")


    else:
        logging.error("XML parsing failed.")

    # Example with a safe XML string
    safe_xml_string = "<root><element attribute='safe_value'>Safe data</element></root>"
    safe_root = parse_xml(safe_xml_string)

    if safe_root is not None:
        logging.info("Safe XML parsed successfully.")
        logging.info(ET.tostring(safe_root, encoding='utf8').decode('utf8'))

        # Example of safe data extraction (replace with your actual logic)
        element = safe_root.find('element')
        if element is not None:
            element_text = element.text
            logging.info(f"Extracted text from 'element' element: {element_text}")

            # Example of safe attribute extraction and validation
            attribute_value = element.get('attribute')
            if attribute_value:
                if re.match(r"^[a-zA-Z0-9_]+$", attribute_value):  # Example validation: alphanumeric and underscore only
                    logging.info(f"Extracted attribute 'attribute': {attribute_value}")
                else:
                    logging.warning("Attribute 'attribute' value is invalid.")
            else:
                logging.warning("Attribute 'attribute' not found.")
        else:
            logging.warning("Element 'element' not found.")


    else:
        logging.error("Safe XML parsing failed.")

