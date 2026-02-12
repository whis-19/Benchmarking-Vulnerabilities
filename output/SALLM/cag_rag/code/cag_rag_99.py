from flask import Flask, request, make_response, jsonify
import lxml.etree
from defusedxml.lxml import fromstring, tostring
import secrets
import os

app = Flask(__name__)

# Generate a secret key for the app
SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
app.config['SECRET_KEY'] = SECRET_KEY

@app.before_request
def before_request():
    """
    Before each request, check for CSRF token and set it if not present.
    """
    if request.method == 'POST':
        csrf_token = request.cookies.get('csrf_token')
        form_csrf_token = request.form.get('csrf_token')

        if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
            return jsonify({'error': 'CSRF token validation failed'}), 400

@app.after_request
def after_request(response):
    """
    After each request, set the CSRF token if not already present.
    """
    if 'csrf_token' not in request.cookies:
        csrf_token = secrets.token_hex(16)
        response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure and HttpOnly flags
    return response

@app.route('/get_csrf_token', methods=['GET'])
def get_csrf_token():
    """
    Endpoint to get a new CSRF token.  This should be called before displaying the form.
    """
    csrf_token = secrets.token_hex(16)
    resp = jsonify({'csrf_token': csrf_token})
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
    return resp

@app.post("/parse_xml")
def parse_xml():
    """
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string using defusedxml to prevent XXE attacks.
    :return: The XML as a string.
    """
    try:
        xml_src = request.form.get('xml_src')

        if not xml_src:
            return jsonify({'error': 'Missing xml_src parameter'}), 400

        # Use defusedxml to parse the XML safely
        try:
            xml_doc = fromstring(xml_src)
            xml_string = tostring(xml_doc, encoding='utf8').decode('utf8')
            return jsonify({'xml': xml_string}), 200
        except lxml.etree.XMLSyntaxError as e:
            return jsonify({'error': f'Invalid XML: {str(e)}'}), 400
        except Exception as e:
            return jsonify({'error': f'Error parsing XML: {str(e)}'}), 500

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server.
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

