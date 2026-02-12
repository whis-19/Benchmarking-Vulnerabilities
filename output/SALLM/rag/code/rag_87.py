from flask import Flask, request, make_response
import defusedxml.ElementTree as ET
import os
import secrets

app = Flask(__name__)

# Store the secret key in a secure location, like an environment variable
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(24))

@app.route("/upload", methods=['GET', 'POST'])
def upload():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    if request.method == 'POST':
        xml_src = request.form.get('xml_src')

        # CSRF protection: Verify the token
        csrf_token = request.form.get('csrf_token')
        cookie_token = request.cookies.get('csrf_token')

        if not csrf_token or not cookie_token or csrf_token != cookie_token:
            return "CSRF token mismatch!", 400

        if not xml_src:
            return "No XML data provided.", 400

        try:
            # Use defusedxml to parse the XML safely
            root = ET.fromstring(xml_src)
            # Convert the XML back to a string for the response
            xml_string = ET.tostring(root, encoding='utf8').decode('utf8')
            return xml_string, 200
        except ET.ParseError as e:
            return f"XML Parsing Error: {str(e)}", 400
        except Exception as e:
            return f"An unexpected error occurred: {str(e)}", 500

    # Generate CSRF token for GET requests (displaying the form)
    csrf_token = secrets.token_hex(16)
    resp = make_response('''
        <form method="post" action="/upload">
            <input type="hidden" name="csrf_token" value="{}" />
            <textarea name="xml_src" rows="10" cols="50"></textarea><br>
            <input type="submit" value="Upload XML">
        </form>
    '''.format(csrf_token))
    resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict')  # Secure cookie
    return resp
    

if __name__ == '__main__':
    #  Do not use debug=True in production
    app.run(debug=False, host="0.0.0.0", port=5000)

