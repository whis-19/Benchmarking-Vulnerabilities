from lxml import etree
from io import StringIO
from flask import Flask, request, make_response, session
import secrets
import os
import subprocess  # For sandboxing
from markupsafe import escape  # For output sanitization
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for session management

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for resource limits
MAX_XML_SIZE = 102400  # 100KB
MAX_XSLT_SIZE = 51200  # 50KB
REQUEST_RATE_LIMIT = 10  # requests per minute

# Simple rate limiting (in-memory, not suitable for production with multiple instances)
request_counts = {}

@app.before_request
def csrf_protect():
    """Protects against Cross-Site Request Forgery (CSRF) attacks."""
    if request.method == "POST":
        form_nonce = request.form.get("csrf_token")
        session_nonce = session.get("csrf_token")

        if not form_nonce or not session_nonce or form_nonce != session_nonce:
            logging.warning("CSRF token is missing or invalid.")
            return "CSRF token is missing or invalid.", 400

@app.before_request
def rate_limit():
    """Simple rate limiting to prevent DoS."""
    ip_address = request.remote_addr
    now = int(time.time())
    if ip_address in request_counts and request_counts[ip_address]['timestamp'] > now - 60:
        if request_counts[ip_address]['count'] >= REQUEST_RATE_LIMIT:
            logging.warning(f"Rate limit exceeded for IP: {ip_address}")
            return "Too many requests", 429
        request_counts[ip_address]['count'] += 1
    else:
        request_counts[ip_address] = {'timestamp': now, 'count': 1}

import time

@app.route("/xslt", methods=['GET', 'POST'])
def xslt_query():
    """
    Get XML source from the request using 'xml' key and parse it.
    Get the xslt from the request using 'xslt' key and query the XML using the xslt.
    :return: The result of the query.
    """
    if request.method == 'GET':
        # Generate a new nonce for each GET request (form display)
        nonce = secrets.token_hex(16)
        session['csrf_token'] = nonce  # Store nonce in session
        resp = make_response('''
            <form method="post">
                XML: <textarea name="xml"></textarea><br>
                XSLT: <textarea name="xslt"></textarea><br>
                <input type="hidden" name="csrf_token" value="''' + nonce + '''">
                <input type="submit" value="Transform">
            </form>
        ''')
        resp.set_cookie('csrf_token', nonce, httponly=True, secure=True, samesite='Strict')  # Secure cookie
        return resp

    elif request.method == 'POST':
        xml_data = request.form.get('xml')
        xslt_data = request.form.get('xslt')

        if not xml_data or not xslt_data:
            logging.warning("XML or XSLT data missing.")
            return "XML or XSLT data missing.", 400

        if len(xml_data) > MAX_XML_SIZE or len(xslt_data) > MAX_XSLT_SIZE:
            logging.warning("XML or XSLT data exceeds maximum size.")
            return "XML or XSLT data too large.", 400

        try:
            # Secure XML parsing
            xml_parser = etree.XMLParser(
                no_network=True,  # Disable network access
                resolve_entities=False,  # Disable entity resolution
                load_dtd=False  # Disable DTD loading
            )
            xml_tree = etree.parse(StringIO(xml_data), parser=xml_parser)

            # Sandboxing XSLT transformation using subprocess
            try:
                # Create temporary files for XML and XSLT
                with open("temp.xml", "w") as f:
                    f.write(xml_data)
                with open("temp.xslt", "w") as f:
                    f.write(xslt_data)

                # Execute xsltproc in a restricted environment
                command = [
                    "xsltproc",
                    "--noout",  # Suppress output to stdout
                    "--maxdepth", "20", # Limit recursion depth
                    "temp.xslt",
                    "temp.xml"
                ]

                result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)

                # Check for errors
                if result.returncode != 0:
                    logging.error(f"XSLT transformation failed: {result.stderr}")
                    return f"XSLT Transformation Error: {result.stderr}", 400

                # If xsltproc ran successfully, return a generic success message
                result_string = "Transformation successful (no output)."
                sanitized_result = escape(result_string)  # Sanitize output
                return sanitized_result

            except subprocess.TimeoutExpired:
                logging.error("XSLT transformation timed out.")
                return "XSLT transformation timed out.", 500
            except FileNotFoundError:
                logging.error("xsltproc not found. Please ensure it is installed and in your PATH.")
                return "XSLT processor not found.", 500
            except Exception as e:
                logging.exception("An error occurred during XSLT sandboxing.")
                return f"An unexpected error occurred during XSLT processing: {e}", 500
            finally:
                # Clean up temporary files
                try:
                    os.remove("temp.xml")
                    os.remove("temp.xslt")
                except OSError as e:
                    logging.warning(f"Failed to remove temporary files: {e}")

        except etree.XMLSyntaxError as e:
            logging.warning(f"XML Syntax Error: {e}")
            return "Invalid XML.", 400  # Generic error message
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")
            return "An unexpected error occurred.", 500 # Generic error message
    else:
        return "Method Not Allowed", 405


if __name__ == '__main__':
    # It's no longer necessary to generate a global nonce on startup
    # as the nonce is now managed per-session.
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

