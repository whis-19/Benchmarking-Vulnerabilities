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
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def parse_xml_from_file(xml_file_path):
    '''
    Parse XML from a file and return the root element.
    Uses defusedxml to prevent XML vulnerabilities.
    '''
    try:
        tree = DET.parse(xml_file_path) # Use defusedxml's parse
        root = tree.getroot()
        return root
    except FileNotFoundError:
        print(f"Error: File not found at {xml_file_path}")
        return None
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage:  Demonstrates both string and file parsing.

    # Example XML string (replace with your actual XML)
    xml_data = """
    <root>
        <element1 attribute="value1">Text content 1</element1>
        <element2>Text content 2</element2>
    </root>
    """

    # Parse from string
    root_from_string = parse_xml(xml_data)
    if root_from_string:
        print("Parsed XML from string successfully.")
        # Example: Accessing elements
        for element in root_from_string:
            print(f"Element tag: {element.tag}, text: {element.text}, attributes: {element.attrib}")


    # Create a temporary XML file for demonstration
    with open("temp.xml", "w") as f:
        f.write(xml_data)

    # Parse from file
    root_from_file = parse_xml_from_file("temp.xml")
    if root_from_file:
        print("\nParsed XML from file successfully.")
        # Example: Accessing elements
        for element in root_from_file:
            print(f"Element tag: {element.tag}, text: {element.text}, attributes: {element.attrib}")

    # Clean up the temporary file (optional)
    import os
    os.remove("temp.xml")

