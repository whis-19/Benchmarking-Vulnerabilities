from flask import Flask, request, make_response
import lxml.etree
import secrets
import os

app = Flask(__name__)

# Generate a CSRF token
def generate_csrf_token():
    return secrets.token_hex(16)

# Set the CSRF token in a cookie
@app.after_request
def set_csrf_cookie(response):
    if 'csrf_token' not in request.cookies:
        csrf_token = generate_csrf_token()
        response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure, HttpOnly, and Strict SameSite
    return response

@app.route('/get_csrf', methods=['GET'])
def get_csrf():
    """
    Endpoint to get the CSRF token.  This is necessary because the cookie is HttpOnly.
    """
    csrf_token = generate_csrf_token()
    resp = make_response({"csrf_token": csrf_token})
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
    return resp

@app.post("/upload")
def upload():
    '''
    Get the xml_src from the request, parse it and return it as string.
    '''
    csrf_token = request.cookies.get('csrf_token')
    form_csrf_token = request.form.get('csrf_token')

    if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
        return "CSRF token validation failed.", 400

    xml_src = request.form.get("xml_src")

    if not xml_src:
        return "No XML data provided.", 400

    try:
        # Disable DTD processing and external entity resolution
        parser = lxml.etree.XMLParser(
            no_network=True,  # Disables network access
            resolve_entities=False, # Disable external entity resolution
            load_dtd=False, # Disable DTD loading
        )

        # Parse the XML data
        root = lxml.etree.fromstring(xml_src.encode('utf-8'), parser=parser)

        # Serialize the XML back to a string (for demonstration purposes)
        xml_string = lxml.etree.tostring(root, encoding='utf-8').decode('utf-8')

        return xml_string, 200

    except lxml.etree.XMLSyntaxError as e:
        return f"XML parsing error: {str(e)}", 400
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}", 500


if __name__ == '__main__':
    # Use a secure, production-ready WSGI server like gunicorn or uWSGI in a real deployment.
    # This development server is for testing purposes only.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

