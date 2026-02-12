from flask import Flask, request, Response
import lxml.etree
from io import StringIO, BytesIO

app = Flask(__name__)

@app.post("/parse_xml")
def parse_xml():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    try:
        xml_src = request.form.get('xml_src')

        if not xml_src:
            return Response("Missing 'xml_src' parameter.", status=400, mimetype='text/plain')

        # Use BytesIO to handle potential encoding issues and prevent XXE
        xml_bytes = xml_src.encode('utf-8')  # Encode to bytes for parsing
        xml_file = BytesIO(xml_bytes)

        # Use lxml.etree.parse with a secure parser configuration to prevent XXE
        parser = lxml.etree.XMLParser(
            no_network=True,  # Disable network access
            resolve_entities=False,  # Disable entity resolution
            load_dtd=False,  # Disable DTD loading
        )

        try:
            tree = lxml.etree.parse(xml_file, parser)
        except lxml.etree.XMLSyntaxError as e:
            return Response(f"XML Syntax Error: {str(e)}", status=400, mimetype='text/plain')
        except Exception as e:
            return Response(f"Error parsing XML: {str(e)}", status=500, mimetype='text/plain')


        # Serialize the XML tree back to a string.  Use encoding='utf-8' for consistency.
        xml_string = lxml.etree.tostring(tree, encoding='utf-8', pretty_print=True).decode('utf-8')

        return Response(xml_string, mimetype='application/xml')

    except Exception as e:
        # Catch any unexpected errors and return a 500 error.
        return Response(f"An unexpected error occurred: {str(e)}", status=500, mimetype='text/plain')


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

