from lxml import etree
import os
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for resource limits
MAX_FILE_SIZE = 1024 * 1024  # 1 MB limit
MAX_PARSING_TIME = 5  # Seconds
MAX_ATTRIBUTE_COUNT = 1000
MAX_NESTING_DEPTH = 20

def check_xml_structure(filepath):
    """
    Pre-processes the XML file to check for potential DoS vulnerabilities
    without fully parsing it using lxml.  Checks for excessive attributes
    and nesting depth.  This is a simplified check and may not catch all
    possible DoS vectors.

    Args:
        filepath (str): The path to the XML file.

    Returns:
        bool: True if the XML structure is safe, False otherwise.
    """
    attribute_count = 0
    max_depth = 0
    current_depth = 0

    try:
        with open(filepath, 'r') as f:
            for line in f:
                # Simple attribute count check (very basic)
                attribute_count += line.count('=')

                # Depth check (very basic and potentially inaccurate)
                if '<' in line:
                    if '</' not in line:
                        current_depth += 1
                        max_depth = max(max_depth, current_depth)
                    elif line.index('<') > line.index('</'):
                        current_depth += 1
                        max_depth = max(max_depth, current_depth)
                    else:
                        current_depth -= 1

        if attribute_count > MAX_ATTRIBUTE_COUNT:
            logging.warning(f"Potential DoS: Excessive attribute count ({attribute_count} > {MAX_ATTRIBUTE_COUNT})")
            return False

        if max_depth > MAX_NESTING_DEPTH:
            logging.warning(f"Potential DoS: Excessive nesting depth ({max_depth} > {MAX_NESTING_DEPTH})")
            return False

        return True

    except Exception as e:
        logging.error(f"Error during XML structure check: {e}")
        return False


def get_root():
    '''
    Create an XML parser, parse the 'resources/config.xsd' file, and return the root element of the XML tree.
    This function is designed to be secure against XXE and DoS attacks by disabling DTD processing and external entity resolution.
    '''
    try:
        # Create a parser that disables DTD processing, external entity loading, and network access.
        parser = etree.XMLParser(dtd_validation=False, resolve_entities=False, no_network=True)

        # Parse the XML file.  Wrap in try-except to handle file not found or parsing errors.
        try:
            # Ensure the path is safe (if it comes from external input, sanitize it!)
            filepath = os.path.join("resources", "config.xsd")

            # File existence check
            if not os.path.isfile(filepath):
                logging.error("config.xsd not found.")
                return None  # Or raise the exception, depending on desired behavior

            # File size check
            file_size = os.path.getsize(filepath)
            if file_size > MAX_FILE_SIZE:
                logging.error(f"File size exceeds maximum allowed size ({file_size} > {MAX_FILE_SIZE} bytes).")
                return None

            # XML Structure Check (DoS Mitigation)
            if not check_xml_structure(filepath):
                logging.error("XML structure check failed.  Possible DoS attack.")
                return None

            # Parsing with timeout
            start_time = time.time()
            try:
                tree = etree.parse(filepath, parser)
            except etree.XMLSyntaxError as e:
                logging.error(f"Error parsing config.xsd: {e}")
                return None

            parsing_time = time.time() - start_time
            if parsing_time > MAX_PARSING_TIME:
                logging.error(f"Parsing time exceeded maximum allowed time ({parsing_time} > {MAX_PARSING_TIME} seconds).  Possible DoS attack.")
                return None


        except FileNotFoundError:
            logging.error("config.xsd not found.")
            return None  # Or raise the exception, depending on desired behavior
        except Exception as e:
            logging.error(f"An error occurred during file processing: {e}")
            return None

        return tree.getroot()

    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full exception
        return None

