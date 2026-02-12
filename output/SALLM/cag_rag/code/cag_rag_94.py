from flask import Flask, request, Response
from lxml import etree
from defusedxml.lxml import fromstring, parse
from defusedxml import defuse_stdlib

app = Flask(__name__)

# Defuse the standard library xml modules to prevent XXE and other XML vulnerabilities
defuse_stdlib()

@app.route('/xpath_query', methods=['POST'])
def xpath_query():
    '''
    Get XML source from the request using 'xml_src' and parse it.
    Get the xpath from the request using 'xpath' and query the XML.
    :return: The result of the query.
    '''
    try:
        xml_src = request.form.get('xml_src')
        xpath_query_str = request.form.get('xpath')

        if not xml_src:
            return Response("Error: xml_src parameter is missing", status=400)

        if not xpath_query_str:
            return Response("Error: xpath parameter is missing", status=400)

        # Parse the XML using defusedxml to prevent XXE attacks
        try:
            xml_doc = fromstring(xml_src.encode('utf-8'))  # Encode to handle unicode
        except Exception as e:
            return Response(f"Error parsing XML: {str(e)}", status=400)

        # Validate the xpath query (very basic example, improve as needed)
        if not isinstance(xpath_query_str, str):
            return Response("Error: xpath must be a string", status=400)

        if len(xpath_query_str) > 200: # Limit xpath length
            return Response("Error: xpath is too long", status=400)

        if any(c in xpath_query_str for c in [';', "'", '"', '--']):
            return Response("Error: xpath contains potentially dangerous characters", status=400)

        # Execute the XPath query
        try:
            results = xml_doc.xpath(xpath_query_str)
            # Convert results to strings for safe output
            stringified_results = [str(result) for result in results]
            return Response(str(stringified_results), status=200)
        except Exception as e:
            return Response(f"Error executing XPath: {str(e)}", status=400)

    except Exception as e:
        return Response(f"Internal Server Error: {str(e)}", status=500)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

