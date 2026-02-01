import xml.etree.ElementTree as ET
import defusedxml.ElementTree as DET
import logging
from defusedxml import configure_parser

# Configure logging (customize as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class XMLParsingError(Exception):
    """Custom exception for XML parsing errors."""
    pass


# Explicitly configure defusedxml parser
parser = configure_parser(forbid_dtd=True, forbid_entities=True, forbid_external=True)
# Optionally, set limits on attribute counts and entity sizes:
# parser.max_attributes = 10  # Example: Limit to 10 attributes per element
# parser.entity_expansion_limit = 1000 # Example: Limit entity expansion

def parse_xml(xml_string):
    '''
    Parse xml_string and return the root element of the XML document.
    Uses defusedxml to prevent XML vulnerabilities.
    Raises XMLParsingError on parsing failure.
    '''
    try:
        root = DET.fromstring(xml_string, parser=parser)  # Use defusedxml's fromstring with explicit parser
        return root
    except DET.ParseError as e:
        logging.error(f"XML parsing error: {e}")
        raise XMLParsingError(f"Invalid XML format: {e}") from e  # Re-raise with custom exception
    except Exception as e:
        logging.exception("An unexpected error occurred during XML parsing:") # Log the full exception
        raise XMLParsingError(f"Unexpected error during XML parsing: {e}") from e


def sanitize_xml_data(data):
    """
    Sanitizes data extracted from XML to prevent injection attacks.
    This is a placeholder; implement actual sanitization based on the context.
    """
    if isinstance(data, str):
        # Example: Escape potentially dangerous characters for HTML output
        data = data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")
        # Example: Remove potentially dangerous characters for command-line arguments
        # data = ''.join(c for c in data if c.isalnum() or c in ['.', '_', '-'])
    return data


# Example usage (safe):
xml_string = "<root><element>Safe Data</element><element>123</element></root>"
try:
    root = parse_xml(xml_string)
    if root is not None:
        print(root.tag)
        # Example of input validation and sanitization:
        for element in root.findall(".//element"):
            data = element.text
            if data is not None:
                # Data type validation
                if data.isdigit():
                    data = int(data)  # Convert to integer if it's a number
                elif not isinstance(data, str):
                    raise ValueError("Element data must be a string or a number")

                # Range check (example for integer data)
                if isinstance(data, int) and (data < 0 or data > 1000):
                    raise ValueError("Integer data out of range")

                # Sanitize the data
                sanitized_data = sanitize_xml_data(data)
                print(f"Sanitized data: {sanitized_data}")

except XMLParsingError as e:
    print(f"Error processing XML: {e}")
except ValueError as e:
    print(f"Data validation error: {e}")


# Example of a potentially vulnerable XML (using regular ET, which is now avoided):
xml_string_vulnerable = """<?xml version="1.0"?>
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
# This XML is vulnerable to a "billion laughs" attack (entity expansion DoS).  defusedxml prevents this.

try:
    root_vulnerable = parse_xml(xml_string_vulnerable) # This will now be handled safely by defusedxml

    if root_vulnerable is not None:
        print(root_vulnerable.tag)
        # Accessing elements would be safe because of defusedxml.
except XMLParsingError as e:
    print(f"Error processing vulnerable XML: {e}")

