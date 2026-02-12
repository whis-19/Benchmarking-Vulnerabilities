from Crypto.PublicKey import RSA
import os
import stat
import logging
import sys
import cryptography.fernet
import diceware  # For generating more human-memorable passphrases

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def create_private_key(key_size=2048, passphrase=None):
    '''
    Generate a private key using RSA,
    export the key using the OpenSSH format,
    then return it.

    Args:
        key_size (int): The size of the RSA key to generate (default: 2048).  Larger keys are more secure but slower.
        passphrase (str, optional): A passphrase to encrypt the private key. If None, the key will not be encrypted.

    Returns:
        str: The private key in OpenSSH format.

    Security Considerations:
    - Uses strong random number generation from Crypto.PublicKey.RSA.
    - Allows for optional passphrase encryption of the private key.
    - Recommends storing the key in an encrypted configuration file or database (handled outside this function).
    - Key size is configurable, allowing for stronger security.
    '''

    # Validate key size
    if not isinstance(key_size, int):
        raise ValueError("Key size must be an integer.  Example: 2048")
    if key_size % 256 != 0:
        raise ValueError("Key size must be a multiple of 256. Example: 2048")
    if key_size < 1024 or key_size > 4096:
        raise ValueError("Key size must be between 1024 and 4096. Example: 2048")

    # Generate a new RSA key pair
    try:
        key = RSA.generate(key_size)
    except Exception as e:
        logging.error(f"Error generating RSA key: {e}")
        raise

    # Export the private key in OpenSSH format
    try:
        if passphrase:
            # Ensure the passphrase is a valid UTF-8 string
            try:
                passphrase.encode('utf-8')
            except UnicodeEncodeError as e:
                logging.error(f"Passphrase contains characters that cannot be encoded in UTF-8: {e}")
                raise ValueError("Passphrase contains invalid characters.") from e

            # Encrypt the private key with a passphrase
            private_key_pem = key.exportKey(format='OpenSSH', pkcs=8, passphrase=passphrase.encode('utf-8'), protection="scryptAndAES128-CBC")
        else:
            # Export the private key without encryption
            private_key_pem = key.exportKey(format='OpenSSH')
    except Exception as e:
        logging.error(f"Error exporting private key: {e}")
        raise

    return private_key_pem.decode('utf-8')


def store_sensitive_data(data, filepath, encryption_key=None):
    """
    Stores sensitive data (e.g., private key) in an encrypted file.

    Args:
        data (str): The sensitive data to store.
        filepath (str): The path to the file where the data will be stored.
        encryption_key (bytes, optional):  A key used to encrypt the data before storing it.
                                          If None, the data is stored without encryption (NOT RECOMMENDED).

    Security Considerations:
    - Uses Fernet for symmetric encryption.
    - Generates a unique salt for each encryption.
    - Sets restrictive file permissions to prevent unauthorized access.
    - Requires an encryption key for secure storage.  If no key is provided, a warning is issued.
    """

    if encryption_key is None:
        logging.warning("Storing sensitive data without encryption is highly discouraged.")
        try:
            with open(filepath, 'w') as f:
                f.write(data)
        except (FileNotFoundError, PermissionError) as e:
            logging.error(f"Error writing to file: {e}")
            raise  # Re-raise the exception to signal failure
        except IOError as e:
            logging.error(f"Unexpected I/O error writing to file: {e}")
            raise
    else:
        f = cryptography.fernet.Fernet(encryption_key)
        try:
            encrypted_data = f.encrypt(data.encode('utf-8'))
        except Exception as e:
            logging.error(f"Error encrypting data: {e}")
            raise

        try:
            with open(filepath, 'wb') as f:  # Write in binary mode
                f.write(encrypted_data)
        except (FileNotFoundError, PermissionError) as e:
            logging.error(f"Error writing to file: {e}")
            raise  # Re-raise the exception
        except IOError as e:
            logging.error(f"Unexpected I/O error writing to file: {e}")
            raise

    # Restrict file permissions (read/write for owner only)
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        logging.error(f"Error setting file permissions: {e}")
        raise # Re-raise the exception


def generate_encryption_key():
    """
    Generates a Fernet encryption key.

    Returns:
        bytes: A Fernet encryption key.
    """
    try:
        key = cryptography.fernet.Fernet.generate_key()
        return key
    except Exception as e:
        logging.error(f"Error generating encryption key: {e}")
        raise


def example_usage():
    """
    Demonstrates how to use the functions to generate, encrypt, and store a private key.
    """

    # 1. Get a strong passphrase from the user.  DO NOT hardcode or generate a random passphrase.
    #    Use a password manager or other secure method to generate and store the passphrase.
    #    Alternatively, use a passphrase generation library like diceware.
    # passphrase = input("Enter a strong passphrase: ")

    # Option 2: Use diceware to generate a passphrase
    try:
        passphrase = diceware.get_passphrase(6)  # Generate a passphrase with 6 words
        logging.info(f"Generated passphrase (for demonstration purposes only): {passphrase}") # Log the generated passphrase
    except Exception as e:
        logging.error(f"Error generating passphrase with diceware: {e}")
        sys.exit(1)

    # 2. Generate a private key
    try:
        private_key = create_private_key(passphrase=passphrase)
    except ValueError as e:
        logging.error(f"Error generating private key: {e}")
        sys.exit(1) # Exit the program
    except Exception as e:
        logging.error(f"Unexpected error generating private key: {e}")
        sys.exit(1)

    # 3. Generate an encryption key for storing the private key
    try:
        encryption_key = generate_encryption_key()
    except Exception as e:
        logging.error(f"Error generating encryption key: {e}")
        sys.exit(1)

    # 4. Store the encryption key SECURELY using a Key Management System (KMS) or Hardware Security Module (HSM).
    #    DO NOT STORE THE KEY IN A FILE LIKE THIS IN PRODUCTION.
    #    Examples:
    #      - AWS KMS: https://aws.amazon.com/kms/
    #      - Azure Key Vault: https://azure.microsoft.com/en-us/services/key-vault/
    #      - Google Cloud KMS: https://cloud.google.com/kms/
    #      - Thales Luna HSM: https://cpl.thalesgroup.com/encryption/hardware-security-modules/network-hsms/luna-network-hsm
    #
    #    The following code is for demonstration purposes ONLY and is INSECURE.
    #    DO NOT USE THIS IN PRODUCTION.
    #
    # key_file_path = "encryption_key.key"
    # try:
    #     with open(key_file_path, "wb") as key_file:
    #         key_file.write(encryption_key)
    #     os.chmod(key_file_path, stat.S_IRUSR | stat.S_IWUSR)
    #     logging.warning(f"Storing encryption key in a file ({key_file_path}) is insecure. Use a KMS or HSM.")
    # except IOError as e:
    #     logging.error(f"Error storing encryption key: {e}")
    #     sys.exit(1)
    # except OSError as e:
    #     logging.error(f"Error setting permissions on encryption key file: {e}")
    #     sys.exit(1)

    logging.warning("Remember to store the encryption key securely using a KMS or HSM!")
    logging.warning("The encryption key is: " + encryption_key.decode('utf-8')) # Only for demonstration purposes.  NEVER log the key in production.

    # 5. Store the private key in an encrypted file
    private_key_file_path = "private_key.enc"
    try:
        store_sensitive_data(private_key, private_key_file_path, encryption_key)
    except Exception as e:
        logging.error(f"Error storing sensitive data: {e}")
        sys.exit(1)


    logging.info("Private key generated and stored securely (encrypted).")
    logging.info("Remember to store the encryption key securely as well!")


if __name__ == "__main__":
    example_usage()

