from flask import Flask, request, make_response, render_template_string, session
from defusedxml.lxml import fromstring, tostring
import secrets
import os
import logging

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(24))  # Important for session security

# Configure logging
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
try:
    logging.basicConfig(level=log_level)
except ValueError:
    logging.basicConfig(level=logging.INFO)  # Default to INFO if LOG_LEVEL is invalid
    logger = logging.getLogger(__name__)
    logger.warning(f"Invalid LOG_LEVEL: {log_level}.  Defaulting to INFO.")

logger = logging.getLogger(__name__)


# Generate a unique nonce for form validation
def generate_nonce():
    return secrets.token_hex(16)

# Validate the nonce
def validate_nonce(form_nonce, session_nonce):
    return form_nonce and session_nonce and form_nonce == session_nonce

@app.route('/')
def index():
    nonce = generate_nonce()
    session['nonce'] = nonce  # Store nonce in session
    resp = make_response(render_template_string('''
        <form method="POST" action="/parse_xml">
            <input type="hidden" name="nonce" value="{{ nonce }}">
            <textarea name="xml_src"></textarea>
            <button type="submit">Parse XML</button>
        </form>
    ''', nonce=nonce))
    # No need to set cookie for nonce anymore
    return resp

@app.post("/parse_xml")
def parse_xml():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string, preventing XXE attacks.
    :return: The XML as a string.
    '''
    try:
        xml_src = request.form.get('xml_src')
        form_nonce = request.form.get('nonce')
        session_nonce = session.pop('nonce', None)  # Get nonce from session and remove it

        if not validate_nonce(form_nonce, session_nonce):
            logger.warning("CSRF attempt detected: Invalid nonce.")
            return "Invalid request.", 400  # Generic error message

        if not xml_src:
            logger.warning("No XML data provided.")
            return "Invalid request.", 400  # Generic error message

        # Use defusedxml to prevent XXE attacks
        try:
            xml_doc = fromstring(xml_src)
            xml_string = tostring(xml_doc, pretty_print=True).decode('utf-8')
            return xml_string, 200, {'Content-Type': 'application/xml'}
        except lxml.etree.XMLSyntaxError as e:
            logger.error(f"XML parsing error: {str(e)}")
            return "Invalid XML format.", 400  # Generic error message
        except Exception as e:
            logger.exception("An unexpected error occurred during XML processing.")
            return "An unexpected error occurred.", 500  # Generic error message

    except Exception as e:
        logger.exception("An error occurred in parse_xml route.")
        return "An unexpected error occurred.", 500  # Generic error message

if __name__ == '__main__':
    # Use HTTPS in production
    # Use a production WSGI server like gunicorn or uwsgi
    app.run(debug=False, host="127.0.0.1", port=int(os.environ.get("PORT", 8080)))

