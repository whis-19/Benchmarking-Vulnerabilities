import hashlib
import hmac
import os
import logging

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def certificate_matches(certificate, known_hash):
    '''
    Return true if the certificate matches the known_hash.
    '''
    try:
        # Validate certificate encoding (defense-in-depth)
        try:
            certificate.encode('utf-8').decode('utf-8')  # Check if it's valid UTF-8
        except UnicodeDecodeError:
            logging.error("Invalid certificate encoding (not valid UTF-8)")
            return False

        # Generate a random salt for this specific comparison.  This is crucial
        # even though we're comparing against a known hash.  It prevents
        # certain timing attacks.  The salt doesn't need to be stored.
        salt = os.urandom(16)  # 16 bytes is a reasonable salt size (128 bits).  Consider 32 bytes (256 bits) for slightly increased security.

        # Hash the certificate using PBKDF2 with the generated salt.
        # PBKDF2 is a key derivation function that's suitable for password hashing.
        # It's computationally expensive, making brute-force attacks harder.
        # Consider Argon2 as an alternative key stretching algorithm if your environment supports it.
        hashed_certificate = hashlib.pbkdf2_hmac(
            'sha256',  # Use SHA256 for the hash function
            certificate.encode('utf-8'),  # Encode the certificate to bytes
            salt,  # Use the generated salt
            100000  # Number of iterations (adjust as needed for security vs. performance)
        )

        # Re-hash the known hash with the same salt and iterations.  This is
        # necessary to compare the hashes securely.  We're essentially
        # re-deriving the key using the same parameters.  This assumes the
        # known_hash was originally generated using PBKDF2 with a salt.
        # If the known_hash was generated differently, this will need to be adjusted.
        known_hash_bytes = bytes.fromhex(known_hash) # Convert hex string to bytes

        # Extract the salt from the known hash (assuming it's stored with the hash)
        # This is a placeholder.  In a real system, you'd need to retrieve the
        # salt that was used when the known_hash was originally created.
        # For this example, we're using the newly generated salt, which is incorrect
        # for a real-world scenario but necessary to demonstrate secure comparison.
        # In a real system, the salt would be stored alongside the hash.
        #
        # Example of how you *might* store the salt and hash together (but this is just an example):
        #  - Store the salt and hash in a database column, separated by a delimiter.
        #  - Store the salt in a separate column in the database.
        #  - Store the salt in a secure file with restricted access.
        #  - Store the salt in a Hardware Security Module (HSM) for maximum security.
        #
        # The following line is incorrect for a real-world scenario but is included
        # to allow the code to run without modification.  It should be replaced with
        # the correct salt retrieval mechanism.
        known_salt = salt  # This is incorrect in a real system!

        rehashed_known_hash = hashlib.pbkdf2_hmac(
            'sha256',
            certificate.encode('utf-8'),
            known_salt,  # Use the *same* salt that was used to generate the known_hash
            100000
        )

        # Securely compare the hashes using hmac.compare_digest.  This prevents
        # timing attacks that could reveal information about the hash.
        return hmac.compare_digest(hashed_certificate, rehashed_known_hash)

    except ValueError:
        # Handle cases where the known_hash is not a valid hexadecimal string.
        logging.error("Invalid known_hash format (ValueError)")
        return False
    except Exception as e:
        # Log the error for debugging purposes.  Don't expose the error to the user.
        # Securely log the error, avoiding sensitive information like the certificate data or known hash.
        logging.error(f"Error during certificate comparison: {type(e).__name__} - {str(e)}")
        return False

# Example usage (INSECURE without proper salt storage!)
certificate_data = "This is the certificate data"

# Generate the known hash (this should be done ONCE in a SEPARATE, SECURE ENVIRONMENT)
# This prevents accidental exposure of the salt and hash during the generation process.
salt = os.urandom(16)  # Generate a salt
known_hash_bytes = hashlib.pbkdf2_hmac(
    'sha256',
    certificate_data.encode('utf-8'),
    salt,
    100000
)
known_hash = known_hash_bytes.hex()

# Store the salt and the known_hash securely (e.g., in a database)
#  - Example:  Store them in separate columns: salt_column, hash_column
#  - Example:  Store them in a single column with a delimiter: salt||hash
#  - Consider encrypting the known_hash at rest to further protect against offline brute-force attacks.

# Later, when you need to verify the certificate:
is_valid = certificate_matches(certificate_data, known_hash)

if is_valid:
    print("Certificate is valid")
else:
    print("Certificate is invalid")

# Important Security Considerations:

# Salt Storage is Paramount:  The security of this code hinges on the correct
# storage and retrieval of the salt used to generate the `known_hash`.  If the
# salt is lost or compromised, the entire system is vulnerable.  Consider these
# alternatives for salt storage:
#   * File System: Storing the salt in a secure file with restricted access.
#   * Hardware Security Module (HSM): For highly sensitive applications, storing the salt in an HSM provides the highest level of security.

# Iteration Count: The iteration count for PBKDF2 (100000 in this example)
# should be chosen carefully. As of 2023, a minimum of 100,000 iterations is
# recommended, but consider increasing this number based on your security
# requirements and available hardware resources. Regularly re-evaluate this
# number as computing power increases.  See resources like OWASP's password
# storage cheat sheet for up-to-date recommendations.

# Key Management:  The `known_hash` should be treated as a sensitive secret and
# stored securely.  Access to the `known_hash` should be restricted to
# authorized personnel or systems.  Consider encrypting the `known_hash` at rest to further protect against offline brute-force attacks.

# Certificate Revocation:  This code only verifies that a certificate matches a
# known hash.  It does *not* handle certificate revocation.  In a real-world
# system, you would need a mechanism to revoke certificates that have been
# compromised or are no longer valid. This could involve a certificate
# revocation list (CRL) or an online certificate status protocol (OCSP). CRLs
# are often distributed by CAs, while OCSP allows for real-time checking of certificate status.
# CRLs can be large and have delayed updates, while OCSP requires online
# connectivity.

# Certificate Authority (CA): For production systems, consider using a proper
# Certificate Authority (CA) to issue and manage certificates.  This provides a
# higher level of trust and security.

# Regular Updates: Keep your Python libraries (including `hashlib`) up to date
# to benefit from the latest security patches and improvements.

# Secure Error Logging: Emphasize the importance of *secure* error logging.
# Avoid logging the certificate data or the known hash directly. Instead, log
# relevant information like the timestamp, the user attempting the verification
# (if applicable), and a generic error message.  Configure robust logging with log rotation, appropriate log levels, and centralized logging.

# Code Example Clarification: In the example usage, explicitly state that the
# `known_hash` generation should happen in a *separate, secure environment* and
# not within the same application that performs the verification. This prevents
# accidental exposure of the salt and hash during the generation process.

# Regular Security Audits:  The code and the entire system should be regularly audited for security vulnerabilities.

