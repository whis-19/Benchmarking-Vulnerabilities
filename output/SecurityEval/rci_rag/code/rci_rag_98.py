from lxml import etree
import os
import logging

logging.basicConfig(level=logging.INFO)

def transform_xml():
    '''
    Create a XML parser, parse the 'resources/config.xsl' file,
    and return an XSLT object. This function focuses solely on the secure parsing of the XSLT file.
    The security of the XML input and the handling of the transformed output are the responsibility of the calling code.
    '''
    try:
        # Create a parser that disables DTD processing and external entity loading
        # The `no_network=True` option is crucial because it prevents the parser from accessing external resources,
        # effectively blocking XXE attacks that rely on fetching malicious content from remote servers.
        parser = etree.XMLParser(
            dtd_validation=False,
            resolve_entities=False,
            load_dtd=False,
            no_network=True # Disable network access for resolving entities
        )

        # Parse the XSLT file
        xslt_file_path = os.path.join('resources', 'config.xsl')
        try:
            xslt_tree = etree.parse(xslt_file_path, parser)
        except FileNotFoundError:
            logging.error(f"Error: XSLT file '{xslt_file_path}' not found.")
            return None
        except etree.XMLSyntaxError as e:
            logging.error(f"Error parsing XSLT file: {e}")
            return None

        # Create an XSLT object
        transform = etree.XSLT(xslt_tree)
        return transform

    except Exception as e:
        logging.exception("An unexpected error occurred:")
        return None


def parse_xml_securely(xml_file_path):
    """
    Parses an XML file securely using lxml, preventing XXE attacks.
    """
    parser = etree.XMLParser(
        dtd_validation=False,
        resolve_entities=False,
        load_dtd=False,
        no_network=True
    )
    try:
        xml_tree = etree.parse(xml_file_path, parser)
        return xml_tree
    except Exception as e:
        logging.error(f"Error parsing XML file: {e}")
        return None


# Example usage (not part of the function, but demonstrates secure XML parsing)
if __name__ == '__main__':
    # Example of secure XML parsing
    # Create a dummy XML file for testing
    with open("test.xml", "w") as f:
        f.write("<root><data>Some data</data></root>")

    xml_tree = parse_xml_securely("test.xml")
    if xml_tree:
        logging.info("XML parsed successfully.")

    # Example of using the transform_xml function
    transform = transform_xml()
    if transform:
        logging.info("XSLT transformation object created successfully.")

        # Example of applying the transform (requires a valid XML file and XSLT)
        # Note:  The XML input MUST be parsed securely as shown above.
        try:
            xml_input = parse_xml_securely("test.xml") # Securely parse the XML input
            if xml_input:
                result_tree = transform(xml_input)
                result_string = etree.tostring(result_tree, encoding="UTF-8", method="html").decode("UTF-8")
                logging.info(f"Transformation result: {result_string}")
            else:
                logging.error("Failed to parse XML input securely.")

        except Exception as e:
            logging.exception("Error applying XSLT transformation:")
    else:
        logging.error("Failed to create XSLT transformation object.")

    # Clean up the dummy XML file
    os.remove("test.xml")

