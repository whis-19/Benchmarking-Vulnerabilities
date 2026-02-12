from Crypto.PublicKey import DSA
from Crypto import Random
import os

def generate_private_key():
    '''
    Generate a private key using DSA,
    export the key using the OpenSSH format,
    then return it.
    '''
    try:
        # Generate a DSA key pair.  Use a strong random number generator.
        key = DSA.generate(bits=2048, randfunc=Random.get_random_bytes)

        # Export the private key in OpenSSH format.  This is generally preferred
        # over other formats for security and compatibility.
        private_key_pem = key.export_key(format='OpenSSH')

        return private_key_pem

    except Exception as e:
        print(f"Error generating DSA key: {e}")
        return None

if __name__ == '__main__':
    private_key = generate_private_key()

    if private_key:
        # IMPORTANT:  This is just for demonstration.  DO NOT print the private key
        # to the console in a real application.  Store it securely!
        print("Generated Private Key (DO NOT PRINT IN PRODUCTION):")
        print(private_key.decode())

        # Example of how to store the key securely (replace with your actual secure storage):
        # In a real application, you would store this key in a secure location,
        # such as an encrypted file or a hardware security module (HSM).
        # The following is just a placeholder and is NOT secure.
        # with open("private_key.pem", "wb") as f:
        #     f.write(private_key)
        # os.chmod("private_key.pem", 0o600) # Restrict access to the file

        print("\nKey generated successfully.  Remember to store it securely!")
    else:
        print("Key generation failed.")

