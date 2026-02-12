from Crypto.PublicKey import DSA
from Crypto import Random
import os
import secrets
import base64

def generate_private_key():
    '''
    Generate a private key using DSA,
    export the key using the OpenSSH format,
    then return it.
    '''

    # Use a cryptographically secure random number generator.
    random_gen = Random.new().read

    # Generate a DSA key pair.  The key size (1024) should be chosen based on security requirements.
    # Larger key sizes offer better security but require more computational resources.
    key = DSA.generate(1024, random_gen)

    # Export the private key in OpenSSH format.  This format is widely supported.
    private_key_pem = key.export_key(format='OpenSSH')

    # Ensure proper output encoding (UTF-8 is a good default).
    private_key_pem_str = private_key_pem.decode('utf-8')

    return private_key_pem_str

def generate_and_store_key(filepath):
    """
    Generates a DSA private key, exports it in OpenSSH format, and stores it in a file.
    Includes security considerations for file permissions.
    """
    private_key = generate_private_key()

    # Write the key to a file with restricted permissions.  This is crucial to prevent unauthorized access.
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(private_key)

        # Set file permissions to read/write for the owner only (0600).
        os.chmod(filepath, 0o600)  # Octal notation for file permissions
    except OSError as e:
        print(f"Error writing key to file: {e}")
        return False

    return True

def generate_random_password(length=16):
    """
    Generates a cryptographically secure random password.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

def hash_password(password):
    """
    Hashes a password using a strong one-way hash function (bcrypt).
    """
    import bcrypt
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def verify_password(password, hashed_password):
    """
    Verifies a password against a bcrypt hash.
    """
    import bcrypt
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# Example Usage (Demonstration -  DO NOT HARDCODE KEYS OR PASSWORDS IN REAL APPLICATIONS)
if __name__ == '__main__':
    # Generate and store a private key
    key_file = "my_private_key.pem"
    if generate_and_store_key(key_file):
        print(f"Private key generated and stored in {key_file}")

    # Generate a random password
    new_password = generate_random_password()
    print(f"Generated password: {new_password}")

    # Hash the password
    hashed_password = hash_password(new_password)
    print(f"Hashed password: {hashed_password}")

    # Verify the password
    if verify_password(new_password, hashed_password):
        print("Password verification successful!")
    else:
        print("Password verification failed.")

    # Example of using the generated private key (replace with actual usage)
    # In a real application, you would load the key from the file and use it for signing or encryption.
    # This example just prints the first few lines of the key.
    try:
        with open(key_file, 'r', encoding='utf-8') as f:
            key_content = f.readlines()
            print("First few lines of the stored private key:")
            for i in range(min(5, len(key_content))):  # Print up to 5 lines
                print(key_content[i].strip())
    except FileNotFoundError:
        print(f"Error: Key file {key_file} not found.")
    except Exception as e:
        print(f"Error reading key file: {e}")

