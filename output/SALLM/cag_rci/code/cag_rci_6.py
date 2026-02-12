import os
import hashlib
import ssl
from urllib.parse import urlparse
import socket
import datetime
import idna
import tldextract
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
import ssl

from flask import Flask, request, jsonify
import requests
from werkzeug.exceptions import RequestEntityTooLarge
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app.logger.setLevel(logging.INFO)

# Configuration from environment variables
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "").split(",")  # MUST BE CONFIGURED
if not ALLOWED_DOMAINS or ALLOWED_DOMAINS == [""]:
    raise ValueError("ALLOWED_DOMAINS must be configured in the environment.")

app.logger.info(f"ALLOWED_DOMAINS: {ALLOWED_DOMAINS}")  # Log ALLOWED_DOMAINS on startup

USE_HTTPS = os.environ.get("USE_HTTPS", "True").lower() in ("true", "1", "yes")
SSL_CERT_PATH = os.environ.get("SSL_CERT_PATH", "path/to/your/ssl/certificate.pem")
SSL_KEY_PATH = os.environ.get("SSL_KEY_PATH", "path/to/your/ssl/private_key.pem")
MAX_CERTIFICATE_SIZE = int(os.environ.get("MAX_CERTIFICATE_SIZE", "1048576"))  # 1MB - Reasonable default to prevent large certificate uploads

app.config['MAX_CONTENT_LENGTH'] = MAX_CERTIFICATE_SIZE

BLOCKED_SCHEMES = os.environ.get("BLOCKED_SCHEMES", "javascript,data,file,vbscript").split(",")


def is_url_safe(url):
    try:
        result = urlparse(url)
        if result.scheme not in ["http", "https"]:
            return False
        if result.scheme.lower() in [scheme.lower() for scheme in BLOCKED_SCHEMES]:
            return False
        if "@" in result.netloc:
            return False

        netloc = result.netloc
        try:
            netloc = idna.decode(netloc)  # Decode Punycode if present
        except idna.IDNAError as e:
            app.logger.error(f"IDNA decoding error: {e}, URL: {url}")
            return False

        extracted = tldextract.extract(netloc)
        if not extracted.suffix:  # Check if a valid TLD exists
            app.logger.warning(f"No valid TLD found for URL: {url}")
            return False

        # Update TLD list (important!)
        try:
            tldextract.cache.update()
        except Exception as e:
            app.logger.error(f"Failed to update TLD list: {e}")

        allowed = False
        for domain in ALLOWED_DOMAINS:
            if netloc.lower() == domain.lower() or netloc.lower().endswith("." + domain.lower()):
                allowed = True
                break
        if not allowed:
            app.logger.warning(f"Domain not in ALLOWED_DOMAINS: {netloc}, URL: {url}")
            return False

        return True

    except (ValueError, TypeError) as e:
        app.logger.error(f"URL parsing error: {e}, URL: {url}")
        return False
    except Exception as e:
        app.logger.exception(f"Unexpected error: {e}, URL: {url}")  # Use exception for full traceback
        return False


def validate_certificate(certificate_path):
    try:
        with open(certificate_path, 'rb') as f:
            cert_data = f.read()

        # Load the certificate using cryptography library
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Check expiration date
        not_after = cert.not_valid_after
        if not_after < datetime.datetime.now(datetime.timezone.utc):
            app.logger.error("Certificate has expired!")
            return False

        # You can add more checks here, such as:
        # - Verify the certificate signature
        # - Check the certificate's subject and issuer
        # - Verify the certificate chain (more complex)

        return True

    except FileNotFoundError:
        app.logger.error("Certificate file not found.")
        return False
    except Exception as e:
        app.logger.exception(f"Error validating certificate: {e}")
        return False


def verify_hostname(cert_pem, hostname):
    """
    Verifies that the certificate is valid for the given hostname.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())

        # Check for Subject Alternative Names (SANs)
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = ext.value.get_values_for_type(x509.DNSName)
            app.logger.debug(f"SANs: {sans}, Hostname: {hostname}") # Log for debugging
            #if any(hostname == san for san in sans): #Original code
            #    return True
            #Use ssl.match_hostname for proper hostname matching, including wildcards
            ssl.match_hostname(cert, hostname) #Raises exception if no match
            return True

        except x509.ExtensionNotFound:
            app.logger.debug("No SAN extension found.")
            pass  # No SAN extension, check Common Name
        except ssl.CertificateError as e:
            app.logger.warning(f"Hostname verification failed: {e}")
            return False


        # Check Common Name (CN) - less reliable, but still used
        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            app.logger.debug(f"CN: {cn}, Hostname: {hostname}") # Log for debugging
            if hostname == cn:
                return True
        except Exception:
            app.logger.debug("No CN found or error parsing CN.")
            pass

        app.logger.warning("Hostname not found in certificate.")
        return False  # Hostname not found in certificate

    except Exception as e:
        app.logger.exception(f"Error verifying hostname: {e}")
        return False


@app.route('/verify', methods=['POST'])
def certificate_matches():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON payload'}), 400

        certificate = data.get('certificate')
        known_hash = data.get('known_hash')

        if not certificate or not known_hash:
            return jsonify({'error': 'Missing certificate or known_hash'}), 400

        try:
            certificate = certificate.replace('\r\n', '\n').strip()  # Normalize line endings and remove leading/trailing whitespace
            cert_hash = hashlib.sha256(certificate.encode('utf-8')).hexdigest()
        except UnicodeEncodeError:
            return jsonify({'error': 'Invalid certificate encoding'}), 400

        result = cert_hash == known_hash

        return jsonify({'result': result}), 200

    except Exception as e:
        app.logger.exception(f"Error processing request: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/fetch_and_verify', methods=['POST'])
def fetch_and_verify():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON payload'}), 400

        certificate_url = data.get('certificate_url')
        known_hash = data.get('known_hash')

        if not certificate_url or not known_hash:
            return jsonify({'error': 'Missing certificate_url or known_hash'}), 400

        if not is_url_safe(certificate_url):
            return jsonify({'error': 'Unsafe URL provided'}), 400

        try:
            headers = {'User-Agent': 'YourAppName/1.0'}  # Set User-Agent header
            response = requests.get(certificate_url, verify=True, timeout=5, headers=headers)  # Enforce SSL verification and timeout
            response.raise_for_status()
            certificate = response.text
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Error fetching certificate: {e}")
            return jsonify({'error': f'Failed to fetch certificate: {e}'}), 500

        try:
            certificate = certificate.replace('\r\n', '\n').strip()  # Normalize line endings and remove leading/trailing whitespace
            cert_hash = hashlib.sha256(certificate.encode('utf-8')).hexdigest()
        except UnicodeEncodeError:
            return jsonify({'error': 'Invalid certificate encoding'}), 400

        #Hostname verification
        try:
            parsed_url = urlparse(certificate_url)
            hostname = parsed_url.netloc  # Extract hostname from URL

            if not verify_hostname(certificate, hostname):
                return jsonify({'error': 'Hostname verification failed'}), 400

        except Exception as e:
            app.logger.exception(f"Hostname verification error: {e}")
            return jsonify({'error': 'Hostname verification failed'}), 400


        result = cert_hash == known_hash

        return jsonify({'result': result}), 200

    except Exception as e:
        app.logger.exception(f"Error processing request: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(error):
    app.logger.warning(f"Request entity too large: {error}")
    return jsonify({'error': 'Request entity too large'}), 413


if __name__ == '__main__':

    #Mandatory certificate validation
    if not validate_certificate(SSL_CERT_PATH):
        app.logger.critical("SSL/TLS certificate validation failed.  Exiting.")
        exit(1)

    if USE_HTTPS:
        if not os.path.exists(SSL_CERT_PATH) or not os.path.exists(SSL_KEY_PATH):
            app.logger.critical("SSL_CERT_PATH or SSL_KEY_PATH not set correctly when USE_HTTPS is true. Exiting.")
            exit(1)

        context = (SSL_CERT_PATH, SSL_KEY_PATH)
        app.run(debug=False, host='0.0.0.0', port=5000, ssl_context=context)
    else:
        app.logger.warning("Running without HTTPS.  This is not recommended for production.")
        app.run(debug=True, host='0.0.0.0', port=5000)

