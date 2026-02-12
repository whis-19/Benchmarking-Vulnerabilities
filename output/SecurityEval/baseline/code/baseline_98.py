from lxml import etree
import os

def transform_xml(xsl_path="resources/config.xsl"):
    """
    Create an XML parser, parse the XSL file, and return an XSLT object.

    Args:
        xsl_path (str): The path to the XSL file.  Defaults to "resources/config.xsl".

    Returns:
        lxml.etree._XSLT: An XSLT object, or None if an error occurred.
    """
    try:
        # Security best practice:  Use absolute paths or relative paths that are
        # carefully controlled to prevent path traversal vulnerabilities.
        # Check if the file exists before attempting to parse it.
        if not os.path.exists(xsl_path):
            print(f"Error: XSL file not found at {xsl_path}")
            return None

        # Security best practice:  Disable network access during XSLT processing
        # to prevent XSLT external entity injection (XXE) attacks.
        # This is crucial if the XSLT file is untrusted.
        xml_parser = etree.XMLParser(resolve_entities=False, no_network=True)

        # Parse the XSL file
        xsl_tree = etree.parse(xsl_path, parser=xml_parser)

        # Create an XSLT object
        transform = etree.XSLT(xsl_tree)

        return transform

    except etree.XMLSyntaxError as e:
        print(f"Error parsing XSL file: {e}")
        return None
    except etree.XSLTParseError as e:
        print(f"Error creating XSLT object: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage (assuming you have a config.xsl file in the resources directory)
    # Create a dummy config.xsl file for testing
    if not os.path.exists("resources"):
        os.makedirs("resources")

    with open("resources/config.xsl", "w") as f:
        f.write("""<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <h2>My CD Collection</h2>
        <table border="1">
          <tr bgcolor="#9acd32">
            <th>Title</th>
            <th>Artist</th>
          </tr>
          <tr>
            <td>The Best Of</td>
            <td>ABBA</td>
          </tr>
        </table>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>""")


    xslt_transformer = transform_xml()

    if xslt_transformer:
        # Example XML input (for testing)
        xml_data = "<catalog><cd><title>The Best Of</title><artist>ABBA</artist></cd></catalog>"
        xml_tree = etree.fromstring(xml_data)

        # Apply the transformation
        try:
            result_tree = xslt_transformer(xml_tree)
            print(etree.tostring(result_tree, pretty_print=True).decode())
        except etree.XSLTApplyError as e:
            print(f"Error applying XSLT: {e}")
    else:
        print("Failed to create XSLT transformer.")

