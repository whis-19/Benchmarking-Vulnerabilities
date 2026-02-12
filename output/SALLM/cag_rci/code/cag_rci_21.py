import ipaddress
import socket
import logging
import re
from urllib.parse import urlparse
import validators
import ssl
import datetime
from tldextract import extract
import bleach
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_DOMAINS = ["example.com"]

def is_valid_url(url):
    if not validators.url(url):
        return False

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if not hostname:
        return False

    ext = extract(hostname)
    registered_domain = f"{ext.domain}.{ext.suffix}"

    if registered_domain not in ALLOWED_DOMAINS:
        return False

    return True

def is_valid_hostname(hostname):
    """
    Validates that the hostname is safe.
    """
    if not hostname:
        return False

    # Allow only alphanumeric characters, hyphens, and dots
    if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        return False

    # Check length
    if len(hostname) > 253:  # Maximum hostname length
        return False

    # Prevent internal IP addresses (more robust check)
    try:
        ip_address = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private:
            logging.warning(f"Hostname {hostname} resolves to a private IP address: {ip_address}")
            return False
    except socket.gaierror:
        # Hostname does not resolve.  This *could* be a security risk if the attacker
        # later configures DNS to point this hostname to an internal IP address
        # (DNS rebinding).  Consider returning False here to prevent this attack.
        logging.warning(f"Hostname {hostname} does not resolve. Potential DNS rebinding risk.")
        pass  # Or return False if you require resolvable hostnames
    except ValueError:
        # Handle cases where gethostbyname returns something that's not a valid IP
        logging.warning(f"Hostname {hostname} resolved to an invalid IP address: {ip_address}")
        return False

    return True


def validate_ssl_certificate(hostname, port=443):
    """
    Validates the SSL/TLS certificate of a given hostname.
    """
    if not is_valid_hostname(hostname):
        logging.error(f"Invalid hostname: {hostname}")
        return False

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('DEFAULT:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK')

    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.do_handshake()
                cert = ssock.getpeercert()

                # Check certificate expiration
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if not_after < datetime.datetime.now():
                    logging.error("SSL Certificate Validation Failed: Certificate expired")
                    return False

                # Hostname verification
                try:
                    ssl.match_hostname(ssock, hostname)
                except ssl.CertificateError as e:
                    logging.error(f"SSL Certificate Validation Failed: Hostname mismatch: {e}")
                    return False

                return True
    except socket.gaierror as e:
        logging.error(f"SSL Certificate Validation Failed: Could not resolve hostname: {e}")
        return False
    except ssl.SSLError as e:
        logging.error(f"SSL Certificate Validation Failed: SSL error: {e}")
        return False
    except Exception as e:
        logging.exception(f"SSL Certificate Validation Failed: Unexpected error: {e}") # Use logging.exception to include traceback
        return False


@app.route('/check_url', methods=['GET'])
def check_url():
    target_url = request.args.get('target_url')

    if not target_url:
        return jsonify({"error": "target_url parameter is missing"}), 400

    # Sanitize the input URL to prevent potential HTML/JS injection attacks.
    # Even though the URL isn't directly rendered, it's good practice to sanitize it
    # to prevent it from being exploited in other contexts (e.g., stored in a database).
    target_url = bleach.clean(target_url)

    if not is_valid_url(target_url):
        return jsonify({"error": "Invalid or disallowed URL"}), 400

    parsed_url = urlparse(target_url)
    if parsed_url.scheme == 'https':
        if not validate_ssl_certificate(parsed_url.hostname):
            return jsonify({"error": "Invalid SSL certificate"}), 400

    return jsonify({"result": True}), 200

if __name__ == '__main__':
    #  Never run this in production without proper WSGI server (e.g., gunicorn, uWSGI)
    #  and HTTPS configuration.
    app.run(debug=False, host='0.0.0.0', port=5000)

