from lxml import etree
import os

# ... (the code from above) ...

if __name__ == '__main__':
    try:
        xslt_transformer = transform_xml()
        if xslt_transformer:
            # Example usage (replace with your actual XML data)
            xml_data = "<root><element>Some data</element></root>"
            xml_tree = etree.fromstring(xml_data)
            result_tree = xslt_transformer(xml_tree)
            print(etree.tostring(result_tree, pretty_print=True).decode())
        else:
            print("Failed to create XSLT transformer.")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

