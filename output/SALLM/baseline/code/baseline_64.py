import lxml.etree
from flask import Flask, request, abort
import io

app = Flask(__name__)

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    try:
        xml_src = request.data  # Get raw XML data from the request body

        # Check if XML data is empty
        if not xml_src:
            return "Error: No XML data provided.", 400

        # Use a try-except block to catch potential parsing errors
        try:
            # Parse the XML with security measures:
            # 1. Disable DTD processing to prevent XXE attacks.
            # 2. Disable external entity loading.
            parser = lxml.etree.XMLParser(
                dtd_validation=False,  # Disable DTD validation
                resolve_entities=False,  # Disable external entity resolution
                no_network=True, # Prevent network access
                recover=True # Attempt to recover from errors
            )

            # Parse the XML from the string using io.BytesIO to handle byte strings
            xml_tree = lxml.etree.parse(io.BytesIO(xml_src), parser)

            # Serialize the XML tree back to a string.  Important to use encoding='utf-8'
            # to ensure consistent output.  Also, use xml_declaration=True to include the XML declaration.
            xml_string = lxml.etree.tostring(xml_tree, encoding='utf-8', xml_declaration=True).decode('utf-8')

            return xml_string, 200

        except lxml.etree.XMLSyntaxError as e:
            return f"Error: Invalid XML format. {str(e)}", 400
        except Exception as e:
            return f"Error: An unexpected error occurred during XML parsing. {str(e)}", 500

    except Exception as e:
        return f"Error: An error occurred processing the request. {str(e)}", 500


if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

