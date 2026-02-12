from lxml import etree

    # ... (the transform_xml function from above) ...

    def process_xml(xml_file, xslt_transform):
        """Applies the XSLT transformation to an XML file and prints the result."""
        try:
            parser = etree.XMLParser()  # Or use a safer parser if xml_file is untrusted
            xml_tree = etree.parse(xml_file, parser)
            result_tree = xslt_transform(xml_tree)

            # Handle output encoding and escaping here!  Crucial for security.
            print(etree.tostring(result_tree, encoding="UTF-8", pretty_print=True).decode("UTF-8"))

        except etree.XMLSyntaxError as e:
            print(f"Error parsing XML file: {e}")
        except Exception as e:
            print(f"An error occurred during transformation: {e}")


    if __name__ == "__main__":
        xslt = transform_xml()
        if xslt:
            process_xml("input.xml", xslt)  # Replace "input.xml" with your XML file

