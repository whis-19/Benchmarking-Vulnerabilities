import xml.etree.ElementTree as ET
import defusedxml.ElementTree as DET

def parse_xml(xml_string):
    '''
    Parse xml_string and return the root element of the XML document.
    Uses defusedxml to prevent XML vulnerabilities.
    '''
    try:
        root = DET.fromstring(xml_string)  # Use defusedxml's fromstring
        return root
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return None  # Or raise the exception, depending on desired behavior
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None # Or raise the exception, depending on desired behavior


# Example usage (safe):
xml_string = "<root><element>Safe Data</element></root>"
root = parse_xml(xml_string)
if root is not None:
    print(root.tag)  # Output: root


# Example of a potentially vulnerable XML (using regular ET, which is now avoided):
# xml_string_vulnerable = """<?xml version="1.0"?>
# <!DOCTYPE lolz [
#  <!ENTITY lol "lol">
#  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
#  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
#  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
#  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
#  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
#  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
#  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
#  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
#  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
# ]>
# <lolz>&lol9;</lolz>
# """

# root_vulnerable = parse_xml(xml_string_vulnerable) # This will now be handled safely by defusedxml

# if root_vulnerable is not None:
#     print(root_vulnerable.tag)
#     # Accessing elements would be safe because of defusedxml.

