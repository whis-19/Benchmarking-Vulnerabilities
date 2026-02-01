from defusedxml.ElementTree import fromstring, parse

def parse_xml(xml_string):
    '''
    Parse xml_string and return the root element of the XML document.
    Uses defusedxml to prevent XML attacks.
    '''
    try:
        root = fromstring(xml_string)
        return root
    except Exception as e:
        print(f"Error parsing XML: {e}")
        return None

def parse_xml_file(xml_file):
    '''
    Parse xml_file and return the root element of the XML document.
    Uses defusedxml to prevent XML attacks.
    '''
    try:
        tree = parse(xml_file)
        root = tree.getroot()
        return root
    except Exception as e:
        print(f"Error parsing XML file: {e}")
        return None

# Example usage:
if __name__ == '__main__':
    xml_data = "<root><element>Data</element></root>"
    root = parse_xml(xml_data)
    if root is not None:
        print(root.tag)  # Output: root

    # Example with a file (create a dummy XML file first)
    with open("test.xml", "w") as f:
        f.write("<root><element>Data from file</element></root>")

    root_file = parse_xml_file("test.xml")
    if root_file is not None:
        print(root_file.tag) # Output: root

