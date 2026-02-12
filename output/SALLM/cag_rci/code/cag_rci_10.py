import hashlib
import secrets
import logging
import re  # For input validation

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.INFO, filename='certificate_verification.log', format='%(asctime)s - %(levelname)s - %(message)s')

def certificate_matches(certificate: bytes | str, known_hash: str) -> bool:
    """
    Return True if the certificate matches the known_hash.

    :param certificate: certificate (bytes or string)
    :param known_hash: known hash (string, hex representation)
    :return: True if the certificate matches the known_hash
    """
    try:
        # Ensure the certificate is bytes
        if isinstance(certificate, str):
            try:
                certificate = certificate.encode('utf-8')  # Or appropriate encoding
            except UnicodeEncodeError as e:
                logging.error(f"Error encoding certificate to UTF-8: {e}")
                return False

        # Validate known_hash format
        if not re.match(r"^[0-9a-f]{64}$", known_hash):
            logging.error("Invalid known_hash format. Must be a 64-character hexadecimal string.")
            return False

        # Calculate the SHA-256 hash of the certificate
        calculated_hash = hashlib.sha256(certificate).hexdigest()

        # Compare the calculated hash with the known hash using constant-time comparison
        return secrets.compare_digest(calculated_hash, known_hash)

    except TypeError as e:
        logging.error(f"Invalid certificate type: {e}")
        return False
    except hashlib.Error as e:
        logging.error(f"Hash calculation error: {e}")
        return False
    except Exception as e:
        logging.critical(f"Unexpected error during hash comparison: {e}", exc_info=True)
        return False

# Example Usage (for demonstration purposes only - replace with secure key management)
if __name__ == '__main__':
    # Example certificate (replace with actual certificate data)
    example_certificate = b"This is a sample certificate."

    #  ************************************************************************************
    #  **  SECURITY WARNING:  DO NOT STORE THE HASH IN THE CODE OR A CONFIGURATION FILE! **
    #  **  This is for demonstration purposes ONLY.  In a real application, the        **
    #  **  'known_hash' MUST be retrieved from a secure location like a KMS (Key        **
    #  **  Management System), HSM (Hardware Security Module), or a secure configuration**
    #  **  file with restricted access.  Compromising the 'known_hash' compromises the  **
    #  **  entire verification process.                                                  **
    #  ************************************************************************************

    #  Replace this placeholder with code to retrieve the known_hash from a secure source.
    #  For example:
    #  known_hash = get_hash_from_kms()  # Hypothetical function to retrieve from KMS
    #  known_hash = read_hash_from_secure_config() # Hypothetical function to read from secure config

    known_hash = "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4e162ab59c69960d83a63fd03"  # Example, REPLACE THIS!  This is INSECURE!

    # Test the function
    if certificate_matches(example_certificate, known_hash):
        print("Certificate matches the known hash.")
    else:
        print("Certificate does NOT match the known hash.")

    # Test with an incorrect certificate
    incorrect_certificate = b"This is a different certificate."
    if certificate_matches(incorrect_certificate, known_hash):
        print("Incorrect certificate matches (ERROR!)")
    else:
        print("Incorrect certificate does NOT match (Correct).")

