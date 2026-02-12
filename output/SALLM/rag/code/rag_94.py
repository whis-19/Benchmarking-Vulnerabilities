from lxml import etree
from flask import Flask, request, Response, make_response
import secrets
import os

app = Flask(__name__)

@app.route('/xpath_query', methods=['GET', 'POST'])
def xpath_query():
    '''
    Get XML source from the request using 'xml_src' and parse it.
    Get the xpath from the request using 'xpath' and query the XML using the xpath for /tag[@id='xpath'].
    :return: The result of the query.
    '''
    if request.method == 'POST':
        xml_src = request.form.get('xml_src')
        xpath_query_string = request.form.get('xpath')
        csrf_token = request.form.get('csrf_token')

        # CSRF Protection
        stored_csrf_token = request.cookies.get('csrf_token')
        if not csrf_token or csrf_token != stored_csrf_token:
            return Response("CSRF token is missing or invalid.", status=400)

        if not xml_src or not xpath_query_string:
            return Response("Missing xml_src or xpath parameters.", status=400)

        try:
            # Secure XML parsing
            parser = etree.XMLParser(
                no_network=True,  # Disables network access
                resolve_entities=False, # Disable external entity resolution
                load_dtd=False # Disable DTD loading
            )
            xml_doc = etree.fromstring(xml_src.encode('utf-8'), parser=parser)

            # Execute the XPath query
            result = xml_doc.xpath(xpath_query_string)

            # Convert the result to a string for the response
            result_str = str(result)

            return Response(result_str, content_type='text/plain')

        except etree.XMLSyntaxError as e:
            return Response(f"XML Syntax Error: {str(e)}", status=400)
        except etree.XPathEvalError as e:
            return Response(f"XPath Evaluation Error: {str(e)}", status=400)
        except Exception as e:
            return Response(f"An unexpected error occurred: {str(e)}", status=500)
    else: #GET request
        # Generate CSRF token
        csrf_token = secrets.token_hex(16)

        # Create a response
        resp = make_response('''
            <form method="post">
            XML Source: <textarea name="xml_src"></textarea><br>
            XPath Query: <input type="text" name="xpath"><br>
            <input type="hidden" name="csrf_token" value="''' + csrf_token + '''">
            <input type="submit" value="Submit">
            </form>
        ''')

        # Set the CSRF token as a cookie
        resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict') # Secure and Strict for production
        return resp

if __name__ == '__main__':
    # Use a production WSGI server like gunicorn or uWSGI in production.
    # Never run with debug=True in production.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

