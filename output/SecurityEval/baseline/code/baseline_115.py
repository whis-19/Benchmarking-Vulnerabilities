from lxml import etree
import os

def getXmlRoot(xml_file_path="resources/c.xml"):
    """
    Create an XML parser and parse the specified XML file and return the root element.
    Handles potential errors and uses secure parsing practices.

    Args:
        xml_file_path (str): The path to the XML file.  Defaults to "resources/c.xml".

    Returns:
        etree._Element: The root element of the XML document, or None if an error occurred.
    """
    try:
        # Check if the file exists
        if not os.path.exists(xml_file_path):
            print(f"Error: XML file not found at {xml_file_path}")
            return None

        # Use a secure XML parser to prevent XML External Entity (XXE) attacks
        parser = etree.XMLParser(resolve_entities=False,  # Disable entity resolution
                                 no_network=True,        # Prevent network access
                                 recover=True)           # Recover from errors

        # Parse the XML file
        tree = etree.parse(xml_file_path, parser)
        root = tree.getroot()
        return root

    except etree.XMLSyntaxError as e:
        print(f"Error: XML syntax error in {xml_file_path}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage:
    root = getXmlRoot()

    if root is not None:
        print("XML root element:", root.tag)
        # Example: Iterate through child elements (safely)
        for child in root:
            print("  Child element:", child.tag)
            # Access attributes safely (check if they exist)
            if 'attribute_name' in child.attrib:
                print("    Attribute 'attribute_name':", child.attrib['attribute_name'])
    else:
        print("Failed to parse XML.")

