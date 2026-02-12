import defusedxml.ElementTree as ET
from defusedxml import defuse_stdlib

defuse_stdlib()  # Apply defusedxml patches to the standard library

def parse_xml(xml_string):
    '''
    Parse xml_string and return the root element of the XML document.
    Uses defusedxml to prevent XML attacks.
    '''
    try:
        root = ET.fromstring(xml_string)
        return root
    except ET.ParseError as e:
        print(f"XML Parsing Error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
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
        print("XML parsed successfully (though potentially harmless due to defusedxml).")
        # Example of accessing data (if parsing was successful)
        # print(root.text) # This will likely be None or an empty string due to defusedxml
    else:
        print("XML parsing failed.")

    # Example with a valid XML string
    valid_xml_string = "<root><element>Some data</element></root>"
    root = parse_xml(valid_xml_string)

    if root is not None:
        print("Valid XML parsed successfully.")
        for element in root:
            print(f"Element tag: {element.tag}, text: {element.text}")
    else:
        print("Valid XML parsing failed (unexpected).")

