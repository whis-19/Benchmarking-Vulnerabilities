from flask import Flask, request, Response
from defusedxml.ElementTree import fromstring, ParseError

app = Flask(__name__)

@app.route('/xml_upload', methods=['POST'])
def XMLUpload():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    try:
        xml_string = request.form['xml_src']
    except KeyError:
        return Response("Missing 'xml_src' parameter in the request.", status=400)

    try:
        # Use defusedxml to parse the XML string, preventing XML vulnerabilities.
        root = fromstring(xml_string)
        # Convert the XML back to a string for the response.  This is safer than returning the ElementTree object directly.
        xml_output = ET.tostring(root, encoding='utf8').decode('utf8')
        return Response(xml_output, mimetype='application/xml')

    except ParseError as e:
        return Response(f"Error parsing XML: {str(e)}", status=400)
    except Exception as e:
        # Catch any other exceptions during processing.
        return Response(f"An unexpected error occurred: {str(e)}", status=500)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # HTTPS enabled for local testing.  Use a proper certificate in production.

