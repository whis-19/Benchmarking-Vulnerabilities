from lxml import etree
import os

def get_root():
    '''
    Create an XML parser, parse the 'resources/config.xml' file and return the root.
    '''
    try:
        # Construct the absolute path to the config.xml file.  This is more robust
        # than relying on relative paths, especially in deployed environments.
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, 'resources', 'config.xml')

        # Check if the file exists before attempting to parse it.
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")

        # Use a secure XML parser to prevent XML External Entity (XXE) attacks.
        parser = etree.XMLParser(resolve_entities=False, no_network=True)

        # Parse the XML file.  Handle potential parsing errors gracefully.
        tree = etree.parse(config_path, parser)
        root = tree.getroot()
        return root

    except FileNotFoundError as e:
        print(f"Error: {e}")
        return None  # Or raise the exception, depending on desired behavior

    except etree.XMLSyntaxError as e:
        print(f"Error parsing XML: {e}")
        return None  # Or raise the exception, depending on desired behavior

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None # Or raise the exception, depending on desired behavior


if __name__ == '__main__':
    # Example usage:  Create a dummy config.xml for testing.
    # This part is only executed when the script is run directly.
    if not os.path.exists("resources"):
        os.makedirs("resources")

    config_file_path = os.path.join("resources", "config.xml")
    if not os.path.exists(config_file_path):
        with open(config_file_path, "w") as f:
            f.write("<root><setting1>value1</setting1><setting2>value2</setting2></root>")

    root = get_root()
    if root is not None:
        print("Root element:", root.tag)
        for child in root:
            print(f"  {child.tag}: {child.text}")
    else:
        print("Failed to load XML configuration.")

