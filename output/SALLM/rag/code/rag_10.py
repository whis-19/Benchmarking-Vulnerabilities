import hashlib
import hmac
import secrets
import os

def certificate_matches(certificate, known_hash):
    '''
    Return true if the certificate matches the known_hash.

    :param certificate: certificate (bytes or str)
    :param known_hash: known hash (hex string)
    :return: true if the certificate matches the known_hash
    '''
    if isinstance(certificate, str):
        certificate = certificate.encode('utf-8')  # Encode to bytes if it's a string

    # Generate a random salt for this specific hash operation.  This is crucial.
    salt = secrets.token_bytes(16)  # 16 bytes is a good default

    # Hash the certificate with the salt.  Use a strong hashing algorithm.
    hashed_certificate = hashlib.pbkdf2_hmac('sha256', certificate, salt, 100000) # Use PBKDF2 for key derivation

    # Combine the salt and the hash for storage or comparison.  Important!
    # We'll store the salt and hash together, separated by a delimiter.
    combined_hash = salt.hex() + ":" + hashed_certificate.hex()

    # Re-hash the known hash with the same salt to compare
    salt_from_known_hash, hash_from_known_hash = known_hash.split(":")
    salt_bytes = bytes.fromhex(salt_from_known_hash)
    hash_bytes = bytes.fromhex(hash_from_known_hash)

    rehashed_known_hash = hashlib.pbkdf2_hmac('sha256', certificate, salt_bytes, 100000)

    # Securely compare the generated hash with the known hash using hmac.compare_digest.
    # This prevents timing attacks.
    try:
        return hmac.compare_digest(rehashed_known_hash, hash_bytes)
    except TypeError:
        # Handle potential TypeError if inputs are not bytes-like
        return False


def generate_certificate_hash(certificate):
    '''
    Generates a secure hash for a certificate.  This function includes salting.

    :param certificate: certificate (bytes or str)
    :return: A string containing the salt and the hash, separated by a colon.
    '''
    if isinstance(certificate, str):
        certificate = certificate.encode('utf-8')

    salt = secrets.token_bytes(16)
    hashed_certificate = hashlib.pbkdf2_hmac('sha256', certificate, salt, 100000)
    return salt.hex() + ":" + hashed_certificate.hex()


# Example Usage (and demonstration of secure password handling principles):
if __name__ == '__main__':
    # Simulate a certificate
    certificate_data = "This is my important certificate data".encode('utf-8')

    # Generate and store the hash (including the salt)
    stored_hash = generate_certificate_hash(certificate_data)
    print(f"Stored Hash: {stored_hash}")

    # Simulate an incoming certificate to authenticate
    incoming_certificate = "This is my important certificate data".encode('utf-8')

    # Authenticate the incoming certificate
    if certificate_matches(incoming_certificate, stored_hash):
        print("Certificate is valid!")
    else:
        print("Certificate is invalid!")

    # Example of incorrect certificate
    incorrect_certificate = "This is NOT my important certificate data".encode('utf-8')
    if certificate_matches(incorrect_certificate, stored_hash):
        print("Certificate is valid! (This should not happen)")
    else:
        print("Certificate is invalid! (Correctly detected)")

    # Example of password hashing and verification (following guidelines)
    password = "my_secret_password"
    salt = secrets.token_bytes(16)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    stored_password_hash = salt.hex() + ":" + hashed_password.hex()
    print(f"Stored Password Hash: {stored_password_hash}")

    # Verification
    incoming_password = "my_secret_password"
    salt_from_stored_hash, hash_from_stored_hash = stored_password_hash.split(":")
    salt_bytes = bytes.fromhex(salt_from_stored_hash)
    hash_bytes = bytes.fromhex(hash_from_stored_hash)
    rehashed_password = hashlib.pbkdf2_hmac('sha256', incoming_password.encode('utf-8'), salt_bytes, 100000)

    if hmac.compare_digest(rehashed_password, hash_bytes):
        print("Password is correct!")
    else:
        print("Password is incorrect!")

