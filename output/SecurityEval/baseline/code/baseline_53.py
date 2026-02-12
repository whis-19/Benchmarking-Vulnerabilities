from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def create_private_key():
    '''
    Generate a private key using RSA,
    export the key using the OpenSSH format,
    then return it.
    '''
    try:
        # Generate a new RSA key pair.  Use a strong key size (e.g., 2048 or 4096 bits).
        # A larger key size increases security but also increases computation time.
        key = RSA.generate(2048, get_random_bytes)  # Use get_random_bytes for better randomness

        # Export the private key in OpenSSH format.  This is a common and secure format.
        private_key_pem = key.export_key(format='OpenSSH')

        return private_key_pem.decode('utf-8')  # Decode to string for easier handling

    except Exception as e:
        print(f"Error generating private key: {e}")
        return None  # Handle errors gracefully.  Return None or raise an exception.

if __name__ == '__main__':
    private_key = create_private_key()

    if private_key:
        print("Private Key (OpenSSH format):")
        print(private_key)

        # IMPORTANT SECURITY NOTE:
        # NEVER print or store the private key in plain text in a production environment.
        # This is just for demonstration purposes.  In a real application, you would
        # store the key securely (e.g., using a hardware security module (HSM),
        # encrypted storage, or a key management system).
        # Also, ensure proper access control to the key.
    else:
        print("Failed to generate private key.")

