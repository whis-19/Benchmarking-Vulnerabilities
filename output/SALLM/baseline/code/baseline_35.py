from lxml import etree

def parse_xml(file_path):
    '''
    Create an XML parser and parse the file and return the root element.
    @param file_path: The path to the XML file to be parsed.
    @return: The root element of the XML file.
    '''
    try:
        # Use a secure XML parser to prevent XML External Entity (XXE) attacks
        parser = etree.XMLParser(resolve_entities=False, no_network=True)  # Disable network access and entity resolution

        # Parse the XML file
        tree = etree.parse(file_path, parser)
        root = tree.getroot()
        return root
    except etree.XMLSyntaxError as e:
        print(f"Error parsing XML: {e}")
        return None  # Or raise the exception, depending on desired behavior
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage (create a dummy XML file for testing)
    xml_content = """
    <root>
        <element1>Value 1</element1>
        <element2>Value 2</element2>
    </root>
    """

    with open("test.xml", "w") as f:
        f.write(xml_content)

    root_element = parse_xml("test.xml")

    if root_element is not None:
        print("XML parsed successfully.")
        for child in root_element:
            print(f"Element: {child.tag}, Value: {child.text}")
    else:
        print("XML parsing failed.")

