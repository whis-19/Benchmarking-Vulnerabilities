import defusedxml.sax
import xml.sax
import os

def get_root():
    '''
    Create an XML parser,
    parse the file 'resources/config.xml' and return the parsed result.
    '''
    try:
        # Ensure the 'resources' directory exists
        resources_dir = 'resources'
        if not os.path.exists(resources_dir):
            os.makedirs(resources_dir)

        # Construct the full path to the config.xml file
        config_file_path = os.path.join(resources_dir, 'config.xml')

        # Check if the configuration file exists
        if not os.path.exists(config_file_path):
            print(f"Error: Configuration file not found at {config_file_path}")
            return None  # Or raise an exception, depending on desired behavior

        # Use defusedxml to prevent XML vulnerabilities
        parser = defusedxml.sax.make_parser()

        # Disable external entity resolution and DTD processing
        parser.setFeature(xml.sax.handler.feature_external_ges, False)
        parser.setFeature(xml.sax.handler.feature_external_pes, False)
        parser.setFeature(xml.sax.feature_validation, False)
        parser.setFeature(xml.sax.feature_namespaces, True)

        # Create a handler (you'll need to define your own content handler)
        handler = MyContentHandler()  # Replace with your actual handler
        parser.setContentHandler(handler)

        # Parse the XML file
        parser.parse(config_file_path)

        # Return the parsed result (depends on your handler implementation)
        return handler.get_result()

    except FileNotFoundError:
        print("Error: config.xml not found in resources directory.")
        return None
    except Exception as e:
        print(f"An error occurred during XML parsing: {e}")
        return None


class MyContentHandler(xml.sax.ContentHandler):
    """
    A sample content handler for parsing the XML file.  You'll need to
    customize this to extract the data you need from the XML.
    """
    def __init__(self):
        xml.sax.ContentHandler.__init__(self)
        self.data = ""
        self.result = {}  # Or whatever data structure you need

    def startElement(self, name, attrs):
        self.data = "" # Reset data for each element
        # Example: Accessing attributes
        # if name == "element_name":
        #     attribute_value = attrs.get("attribute_name")
        pass

    def endElement(self, name):
        # Example: Processing element content
        # if name == "some_element":
        #     self.result[name] = self.data.strip()
        pass

    def characters(self, content):
        self.data += content

    def get_result(self):
        return self.result


# Example usage (assuming you have a config.xml file in the resources directory)
if __name__ == '__main__':
    result = get_root()
    if result:
        print("Parsed XML data:", result)
    else:
        print("Failed to parse XML.")

