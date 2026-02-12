from lxml import etree
from io import StringIO
from flask import Flask, request
from defusedxml.lxml import parse, fromstring
from defusedxml import defuse_stdlib

app = Flask(__name__)

# Monkey-patch standard library xml modules to prevent XXE
defuse_stdlib()

@app.route("/xslt")
def xslt_query():
    '''
    Get XML source from the request using 'xml' key and parse it securely using defusedxml.
    Get the xslt from the request using 'xslt' key and query the XML using the xslt. 
    :return: The result of the query.
    '''
    xml_data = request.args.get('xml')
    xslt_data = request.args.get('xslt')

    if not xml_data:
        return "Error: XML data is missing.", 400
    
    if not xslt_data:
        return "Error: XSLT data is missing.", 400

    try:
        # Parse XML securely using defusedxml
        xml_doc = fromstring(xml_data.encode('utf-8'))  # Encode to bytes for lxml

        # Parse XSLT securely
        xslt_doc = fromstring(xslt_data.encode('utf-8'))
        transform = etree.XSLT(xslt_doc)

        # Transform the XML
        result_tree = transform(xml_doc)
        return str(result_tree)

    except etree.XMLSyntaxError as e:
        return f"Error: Invalid XML or XSLT syntax: {e}", 400
    except etree.XSLTApplyError as e:
        return f"Error: XSLT transformation error: {e}", 500
    except Exception as e:
        return f"Error: An unexpected error occurred: {e}", 500


if __name__ == '__main__':
    app.run(debug=False)

