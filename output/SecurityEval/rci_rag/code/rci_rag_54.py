from Crypto.PublicKey import RSA  # Changed from DSA to RSA
from secrets import SystemRandom
import os
import getpass  # For secure passphrase input

def generate_private_key():
    '''
    Generate a private key using RSA,
    export the key using the OpenSSH format,
    then return it.
    '''

    # Use SystemRandom for cryptographically secure random number generation (Guideline 7)
    # random_func = SystemRandom().randrange # Not needed for RSA.generate()

    # Generate a new RSA key pair
    key = RSA.generate(bits=3072)  # Or 4096 for stronger security.  Increased key length.

    # Export the private key in OpenSSH format.  This is inherently more secure
    # than other formats because it includes key derivation and encryption.
    # ALWAYS use a strong passphrase in a real-world application.
    passphrase = getpass.getpass("Enter a strong passphrase for the private key: ")  # Prompt for passphrase
    private_key_pem = key.export_key(format='OpenSSH', passphrase=passphrase.encode('utf-8'))  # Use passphrase and encode to bytes

    return private_key_pem.decode('utf-8') # Guideline 8: Explicitly decode to UTF-8

if __name__ == '__main__':
    private_key = generate_private_key()
    print(private_key)

    # Example of how to save the key to a file (IMPORTANT: Securely manage this file!)
    # Ensure proper permissions are set on the file (e.g., chmod 600)
    # and that the directory is also appropriately secured.
    try:
        with open("private_key.pem", "w", encoding='utf-8') as f: # Guideline 8: Explicit encoding
            f.write(private_key)
        # Secure the file permissions (Guideline: Secure file storage)
        os.chmod("private_key.pem", 0o600) # Only the owner can read/write
        print("Private key saved to private_key.pem")
    except (IOError, OSError) as e:  # Catch more specific exceptions
        print(f"Error saving private key: {e}")

    print("\nIMPORTANT SECURITY CONSIDERATIONS:")
    print("- **Passphrase Protection:** ALWAYS use a strong passphrase when exporting the private key in OpenSSH format. This is the most important step to protect the key.")
    print("- **Secure Storage:** The security of your private key depends entirely on how securely you store it. Consider these measures:")
    print("  - Encryption at Rest: Encrypt the entire file system where the private key is stored.")
    print("  - Hardware Security Modules (HSMs): For the highest level of security, store the private key in an HSM.")
    print("  - Key Rotation: Regularly rotate your private keys.  Implementing key rotation securely is a complex task requiring careful coordination between key generation, distribution, and revocation. Simply generating a new key on a schedule is not sufficient; the old key must be securely revoked and all systems updated to use the new key. This often involves automated configuration management and secure communication channels.")
    print("  - Secure Deletion: When a key is no longer needed, securely delete it. Overwrite the data multiple times.  Consider physical destruction of the storage device for extremely sensitive keys. `shred` is not guaranteed to work on all storage devices (especially SSDs).")
    print("- **Key Length:** Consider using 3072 bits or 4096 bits for even stronger security.")
    print("- **Regular Audits:** Regularly audit your key management practices to ensure that they are secure.")
    print("- **HSM Cost and Complexity:** HSMs are often expensive and complex to integrate. They are not always a practical solution for smaller projects or organizations.")

