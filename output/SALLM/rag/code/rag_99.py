from flask import Flask, request, make_response, render_template_string
import lxml.etree
from defusedxml.lxml import fromstring, tostring
import secrets
import os

app = Flask(__name__)

# CSRF protection
CSRF_TOKEN_NAME = "csrf_token"

def generate_csrf_token():
    """Generates a pseudorandom CSRF token."""
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    """Sets the CSRF token as a cookie."""
    csrf_token = generate_csrf_token()
    response.set_cookie(CSRF_TOKEN_NAME, csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure and HttpOnly flags
    return csrf_token

def validate_csrf_token(request):
    """Validates the CSRF token from the form and cookie."""
    form_token = request.form.get(CSRF_TOKEN_NAME)
    cookie_token = request.cookies.get(CSRF_TOKEN_NAME)

    if not form_token or not cookie_token or form_token != cookie_token:
        return False
    return True

@app.route('/')
def index():
    """Renders a simple form with CSRF protection."""
    response = make_response(render_template_string('''
        <form method="post" action="/parse_xml">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <textarea name="xml_src"></textarea>
            <button type="submit">Parse XML</button>
        </form>
    ''', csrf_token=generate_csrf_token()))  # Generate token on each request
    set_csrf_cookie(response)
    return response

@app.post("/parse_xml")
def parse_xml():
    """
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    """
    if not validate_csrf_token(request):
        return "CSRF token validation failed.", 400

    xml_src = request.form.get('xml_src')

    if not xml_src:
        return "No XML data provided.", 400

    try:
        # Use defusedxml to parse the XML safely
        xml_doc = fromstring(xml_src)

        # Convert the parsed XML back to a string
        xml_string = tostring(xml_doc, encoding="unicode")

        return xml_string, 200

    except lxml.etree.XMLSyntaxError as e:
        return f"XML parsing error: {str(e)}", 400
    except Exception as e:
        # Log the error for debugging purposes.  Crucial for production.
        print(f"An unexpected error occurred: {e}")
        return "An unexpected error occurred during XML processing.", 500

if __name__ == '__main__':
    # Use a production-ready WSGI server in a real deployment.
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

