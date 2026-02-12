from flask import Flask, request, Response
from lxml import etree
from defusedxml.lxml import fromstring, parse
from defusedxml import defuse_stdlib

app = Flask(__name__)

# Defuse the standard library xml modules
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
        xpath_query_string = request.form.get('xpath')

        if not xml_src:
            return Response("Error: xml_src parameter is missing", status=400)
        
        if not xpath_query_string:
            return Response("Error: xpath parameter is missing", status=400)

        # Parse the XML using defusedxml to prevent XML attacks
        try:
            xml_doc = fromstring(xml_src.encode('utf-8'))  # Encode to handle potential Unicode issues
        except Exception as e:
            return Response(f"Error parsing XML: {str(e)}", status=400)

        # Execute the XPath query
        try:
            result = xml_doc.xpath(xpath_query_string)
            
            # Convert the result to a string representation
            result_string = ""
            if isinstance(result, list):
                result_string = ", ".join([str(r) for r in result])
            else:
                result_string = str(result)

            return Response(result_string, content_type='text/plain')

        except Exception as e:
            return Response(f"Error executing XPath: {str(e)}", status=400)

    except Exception as e:
        return Response(f"Internal Server Error: {str(e)}", status=500)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

