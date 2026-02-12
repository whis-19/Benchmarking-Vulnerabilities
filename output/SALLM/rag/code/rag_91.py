from lxml import etree
from io import StringIO
from flask import Flask, request, make_response
import os
import secrets

app = Flask(__name__)

# CSRF protection (using a simple nonce for demonstration - consider using a proper CSRF library)
def generate_nonce():
    return secrets.token_hex(16)

def verify_nonce(form_nonce, cookie_nonce):
    return form_nonce == cookie_nonce

@app.route("/xslt", methods=['POST'])  # Only allow POST requests
def xslt_query():
    '''
    Get XML source from the request using 'xml' key and parse it.
    Get the xslt from the request using 'xslt' key and query the XML using the xslt. 
    :return: The result of the query.
    '''

    # CSRF protection
    nonce = request.cookies.get('csrf_nonce')
    form_nonce = request.form.get('csrf_nonce')

    if not nonce or not form_nonce or not verify_nonce(form_nonce, nonce):
        return "CSRF verification failed", 400

    xml_data = request.form.get('xml')
    xslt_data = request.form.get('xslt')

    if not xml_data or not xslt_data:
        return "Missing XML or XSLT data", 400

    try:
        # Secure XML parsing
        xml_parser = etree.XMLParser(
            no_network=True,  # Disable network access
            resolve_entities=False, # Disable entity resolution
            load_dtd=False  # Disable DTD loading
        )
        xml_tree = etree.parse(StringIO(xml_data), parser=xml_parser)

        # Secure XSLT parsing
        xslt_parser = etree.XMLParser(
            no_network=True,
            resolve_entities=False,
            load_dtd=False
        )
        xslt_tree = etree.parse(StringIO(xslt_data), parser=xslt_parser)
        transform = etree.XSLT(xslt_tree)

        # Transform the XML
        result_tree = transform(xml_tree)
        result = etree.tostring(result_tree, pretty_print=True).decode()

        return result

    except etree.XMLSyntaxError as e:
        return f"XML Syntax Error: {e}", 400
    except etree.XSLTParseError as e:
        return f"XSLT Parse Error: {e}", 400
    except etree.XSLTApplyError as e:
        return f"XSLT Apply Error: {e}", 400
    except Exception as e:
        return f"An unexpected error occurred: {e}", 500

@app.route('/form')
def form():
    nonce = generate_nonce()
    resp = make_response(f"""
    <form action="/xslt" method="post">
        <input type="hidden" name="csrf_nonce" value="{nonce}">
        <label for="xml">XML:</label><br>
        <textarea id="xml" name="xml" rows="4" cols="50"></textarea><br><br>
        <label for="xslt">XSLT:</label><br>
        <textarea id="xslt" name="xslt" rows="4" cols="50"></textarea><br><br>
        <input type="submit" value="Submit">
    </form>
    """)
    resp.set_cookie('csrf_nonce', nonce, httponly=True, secure=True)  # Secure cookie
    return resp

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

