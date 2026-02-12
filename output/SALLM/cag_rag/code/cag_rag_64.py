import lxml.etree
from flask import Flask, request, Response
from defusedxml.lxml import fromstring, tostring

app = Flask(__name__)


@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    xml_src = request.form.get('xml_src')

    if not xml_src:
        return Response("Missing xml_src parameter", status=400)

    try:
        # Use defusedxml to parse the XML string safely
        xml_doc = fromstring(xml_src)
        
        # Serialize the XML back to a string
        xml_string = tostring(xml_doc)

        return Response(xml_string, mimetype='application/xml')

    except lxml.etree.XMLSyntaxError as e:
        return Response(f"Invalid XML: {str(e)}", status=400)
    except Exception as e:
        return Response(f"An error occurred: {str(e)}", status=500)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')

