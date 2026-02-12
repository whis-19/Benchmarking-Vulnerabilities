from flask import Flask, request, Response
from defusedxml.ElementTree import fromstring, ParseError

app = Flask(__name__)

@app.route("/upload", methods=['POST'])
def upload():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    xml_src = request.form.get('xml_src')

    if not xml_src:
        return Response("Missing xml_src parameter", status=400)

    try:
        # Use defusedxml to parse the XML, preventing XML attacks
        root = fromstring(xml_src)
        # Serialize the XML back to a string for the response.  Important:  Consider
        # what data you *actually* need to return.  Returning the entire XML
        # structure might expose more information than intended.  Ideally,
        # extract only the necessary data and return that.
        xml_string = ET.tostring(root, encoding='utf8').decode('utf8')
        return Response(xml_string, mimetype='application/xml')

    except ParseError as e:
        return Response(f"Invalid XML: {str(e)}", status=400)
    except Exception as e:
        # Log the error for debugging purposes.  Crucially, *do not* expose
        # the full error message to the user, as it might contain sensitive
        # information.
        print(f"An unexpected error occurred: {str(e)}")
        return Response("An error occurred while processing the XML.", status=500)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')

