import hashlib
import hmac

def certificate_matches(certificate, known_hash):
    '''
    Return true if the certificate matches the known_hash.

    :param certificate: certificate (bytes or string)
    :param known_hash: known hash (string)
    :return: true if the certificate matches the known_hash
    '''
    try:
        # Ensure the certificate is bytes-like
        if isinstance(certificate, str):
            certificate = certificate.encode('utf-8')

        # Calculate the SHA-256 hash of the certificate
        calculated_hash = hashlib.sha256(certificate).hexdigest()

        # Securely compare the calculated hash with the known hash
        return hmac.compare_digest(calculated_hash, known_hash)

    except Exception as e:
        # Log the error (replace with your actual logging mechanism)
        print(f"Error during certificate hash comparison: {e}")
        return False  # Or raise the exception, depending on desired behavior

