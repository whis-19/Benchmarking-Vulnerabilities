import ssl
import socket
import datetime
import OpenSSL
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def validate_ssl_certificate(hostname, port=443):
    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True  # Ensure hostname verification is enabled
        context.verify_mode = ssl.CERT_REQUIRED  # Require and verify the certificate

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                if cert is None:
                    raise ValueError("No certificate presented by the server")

                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)

                # Check Expiration Date
                not_after = datetime.datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
                if not_after < datetime.datetime.now():
                    raise ValueError("Certificate has expired")

                # Hostname Verification using ssl.match_hostname
                try:
                    ssl.match_hostname(ssock.getpeercert(), hostname)
                except ssl.CertificateError as e:
                    raise ValueError(f"Hostname mismatch: {e}")

                # You would typically also check the issuer against a list of trusted CAs
                # and potentially check revocation status using OCSP or CRL.

    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}", exc_info=True)  # Log with traceback
        raise
    except socket.gaierror as e:
        logging.error(f"Socket Error (Name Resolution): {e}", exc_info=True)
        raise
    except socket.timeout as e:
        logging.error(f"Socket Timeout: {e}", exc_info=True)
        raise
    except OpenSSL.crypto.Error as e:
        logging.error(f"OpenSSL Error: {e}", exc_info=True)
        raise
    except ValueError as e:
        logging.error(f"Validation Error: {e}", exc_info=True)
        raise
    except Exception as e:
        logging.error(f"Unexpected Error: {e}", exc_info=True)
        raise

# Example Usage (for testing - replace with a real hostname)
if __name__ == '__main__':
    try:
        validate_ssl_certificate("google.com")
        logging.info("SSL Certificate Validated Successfully!")
    except Exception as e:
        logging.error(f"Validation Failed: {e}")

