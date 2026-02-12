import secrets
import bcrypt

def generateCryptoKey():
    '''
    Generate a random 128-bit (16-byte) key using secrets.token_bytes().
    This function uses a cryptographically secure random number generator.
    '''
    key = secrets.token_bytes(16)  # 16 bytes * 8 bits/byte = 128 bits
    return key

def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def verify_password(password, hashed_password):
    """Verifies a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        # Handle the case where the hashed_password is not a valid bcrypt hash
        return False  # Or log the error and return False

# Example Usage (Demonstrates key generation and password hashing)
if __name__ == "__main__":
    # Key Generation
    crypto_key = generateCryptoKey()
    print("Generated Crypto Key:", crypto_key.hex())  # Print in hexadecimal for readability

    # Password Hashing Example
    password = "my_secret_password"
    hashed_password = hash_password(password)
    print("Hashed Password:", hashed_password)
    # Note that bcrypt handles salt generation and storage automatically, so you don't need to store the salt separately.

    # Password Verification Example
    is_valid = verify_password(password, hashed_password)
    print("Password Verification:", is_valid)

    # Example of incorrect password verification
    is_valid_incorrect = verify_password("wrong_password", hashed_password)
    print("Password Verification (incorrect password):", is_valid_incorrect)

    print("\nImportant Security Considerations:")
    print("- Rotate keys regularly, with the frequency determined by a risk assessment considering the sensitivity of the data and the potential impact of a key compromise.  Consider rotating keys more frequently if there's any suspicion of compromise.")
    print("- Storing the generated crypto key securely is paramount.  Never store it in plain text, in code, or in configuration files.  Consider using a Hardware Security Module (HSM), Key Management System (KMS), encrypted configuration files, or the operating system's key store.")
    print("- Store hashed passwords securely in a database with appropriate access controls. Protect the database against unauthorized access and data breaches.")
    print("- Implement rate limiting on login attempts to prevent brute-force attacks.  This can be achieved using libraries or framework features designed for rate limiting.")
    print("- Consider using multi-factor authentication for enhanced security.")
    print("- Encourage users to choose strong, unique passwords.")
    print("- Consider implementing password complexity requirements (minimum length, character types) to further enhance security.")
    #print("- If the crypto key is used for encrypting data, consider using a key derivation function (KDF) like `scrypt` or `argon2` to derive the encryption key from the master key and a salt. This adds an extra layer of security.") # Uncomment if applicable

