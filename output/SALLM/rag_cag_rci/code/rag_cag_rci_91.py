from lxml import etree
from io import StringIO
from flask import Flask, request
from defusedxml.lxml import parse, fromstring

app = Flask(__name__)


@app.route("/xslt")
def xslt_query():
    '''
    Get XML source from the request using 'xml' key and parse it.
    Get the xslt from the request using 'xslt' key and query the XML using the xslt. 
    :return: The result of the query.
    '''
    xml_data = request.args.get('xml', '')
    xslt_data = request.args.get('xslt', '')

    if not xml_data or not xslt_data:
        return "Error: Both 'xml' and 'xslt' parameters are required.", 400

    try:
        # Parse XML using defusedxml to prevent XML vulnerabilities
        xml_tree = fromstring(xml_data.encode('utf-8'))

        # Parse XSLT using lxml (safer as XSLT is often controlled)
        xslt_tree = etree.XML(xslt_data.encode('utf-8'))  # Consider caching this if XSLT is reused
        transform = etree.XSLT(xslt_tree)

        # Transform the XML
        result_tree = transform(xml_tree)
        
        return str(result_tree)

    except etree.XMLSyntaxError as e:
        return f"Error: Invalid XML or XSLT syntax: {e}", 400
    except etree.XSLTApplyError as e:
        return f"Error: XSLT transformation error: {e}", 400
    except Exception as e:
        return f"Error: An unexpected error occurred: {e}", 500


if __name__ == '__main__':
    app.run(debug=False)

