from flask import Flask, request, Response
from defusedxml.ElementTree import fromstring, ParseError

app = Flask(__name__)

@app.route("/upload", methods=['POST'])
def upload():
    """
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string using defusedxml to prevent XML attacks.
    :return: The XML as a string, or an error message.
    """
    try:
        xml_src = request.form.get('xml_src')

        if not xml_src:
            return Response("Error: xml_src parameter is missing.", status=400, mimetype='text/plain')

        try:
            # Use defusedxml to parse the XML, preventing XML attacks
            root = fromstring(xml_src)
            # Convert the XML back to a string for the response.  This is safer than returning the ElementTree object directly.
            xml_string = ET.tostring(root, encoding='utf8').decode('utf8')
            return Response(xml_string, mimetype='application/xml')

        except ParseError as e:
            return Response(f"Error parsing XML: {str(e)}", status=400, mimetype='text/plain')

    except Exception as e:
        # Log the error for debugging purposes.  Crucially, do *not* return the raw exception message to the client.
        print(f"Unexpected error: {e}")  # Replace with proper logging
        return Response("Internal server error.", status=500, mimetype='text/plain')


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # HTTPS enabled for testing.  Use a real certificate in production.

