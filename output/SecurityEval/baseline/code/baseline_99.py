import xml.sax
import os

class ConfigHandler(xml.sax.ContentHandler):
    """
    A custom XML content handler to parse the configuration file.
    """
    def __init__(self):
        xml.sax.ContentHandler.__init__(self)
        self.root = None  # Store the root element
        self.current_element = None # Keep track of the current element being parsed
        self.data = "" # Accumulate character data within an element

    def startElement(self, name, attrs):
        """
        Called when the start of an element is encountered.
        """
        if self.root is None:
            self.root = {"name": name, "attributes": dict(attrs), "children": []}
            self.current_element = self.root
        else:
            new_element = {"name": name, "attributes": dict(attrs), "children": [], "parent": self.current_element}
            self.current_element["children"].append(new_element)
            self.current_element = new_element
        self.data = "" # Reset data accumulator

    def endElement(self, name):
        """
        Called when the end of an element is encountered.
        """
        if self.current_element is not None and self.current_element["name"] == name:
            # Store the accumulated data as a "text" child if there's any
            if self.data.strip():
                self.current_element["children"].append({"type": "text", "value": self.data.strip()})

            if "parent" in self.current_element:
                self.current_element = self.current_element["parent"]
            else:
                self.current_element = None # Back to root

        self.data = "" # Reset data accumulator

    def characters(self, content):
        """
        Called when character data is encountered within an element.
        """
        self.data += content


def get_root(filepath="resources/config.xml"):
    """
    Create an XML parser, parse the file and return the parsed result.

    Args:
        filepath (str): The path to the XML configuration file.  Defaults to "resources/config.xml".

    Returns:
        dict: A dictionary representing the parsed XML structure, or None if parsing fails.
    """
    try:
        # Check if the file exists
        if not os.path.exists(filepath):
            print(f"Error: Configuration file not found at {filepath}")
            return None

        # Create a SAX parser
        parser = xml.sax.make_parser()

        # Disable external entity resolution (important for security)
        parser.setFeature(xml.sax.handler.feature_external_ges, False)
        parser.setFeature(xml.sax.handler.feature_external_pes, False)

        # Create a custom content handler
        handler = ConfigHandler()
        parser.setContentHandler(handler)

        # Parse the XML file
        parser.parse(filepath)

        # Return the root element
        return handler.root

    except xml.sax.SAXException as e:
        print(f"Error parsing XML file: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage:
    root = get_root()

    if root:
        print("Parsed XML Root Element:")
        print(root)

        # Example: Accessing data (replace with your actual data structure)
        # Assuming the config.xml has a structure like:
        # <config>
        #   <setting name="database">localhost</setting>
        # </config>

        # Find the 'setting' element with name 'database'
        # for child in root["children"]:
        #     if child["name"] == "setting" and child["attributes"].get("name") == "database":
        #         print(f"Database setting: {child['children'][0]['value']}") # Access the text value
    else:
        print("Failed to parse the XML file.")

