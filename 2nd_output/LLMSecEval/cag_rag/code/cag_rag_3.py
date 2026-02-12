import os
import hashlib
import secrets
import base64
from getpass import getpass  # For secure password input
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Secure Credential Storage and Retrieval ---

def generate_salt():
    """Generates a random salt for password hashing."""
    return secrets.token_hex(16)

def hash_password(password, salt):
    """Hashes the password using PBKDF2HMAC with the provided salt."""
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length
        salt=salt_bytes,
        iterations=100000,  # Adjust iterations for security vs. performance
        backend=default_backend()
    )
    
    return base64.b64encode(kdf.derive(password_bytes)).decode('utf-8')

def verify_password(password, stored_hash, salt):
    """Verifies the password against the stored hash and salt."""
    try:
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
            backend=default_backend()
        )
        kdf.verify(password_bytes, base64.b64decode(stored_hash))
        return True
    except Exception:  # cryptography.exceptions.InvalidKey
        return False

def generate_encryption_key(password, salt):
    """Generates an encryption key from a password and salt using PBKDF2HMAC."""
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for Fernet
        salt=salt_bytes,
        iterations=100000,  # Adjust iterations for security vs. performance
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))

def encrypt_data(data, encryption_key):
    """Encrypts data using Fernet encryption."""
    f = Fernet(encryption_key)
    return f.encrypt(data.encode('utf-8')).decode('utf-8')

def decrypt_data(encrypted_data, encryption_key):
    """Decrypts data using Fernet encryption."""
    f = Fernet(encryption_key)
    return f.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')

def store_credentials(username, password, filename="credentials.dat"):
    """Stores credentials securely (hashed password and encrypted data)."""
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # Generate encryption key from password and salt
    encryption_key = generate_encryption_key(password, salt)

    # Encrypt the username
    encrypted_username = encrypt_data(username, encryption_key)

    # Store the salt, hashed password, and encrypted username
    with open(filename, "w") as f:
        f.write(f"{salt}\n")
        f.write(f"{hashed_password}\n")
        f.write(f"{encrypted_username}\n")
    
    # Secure the file permissions (OS-specific)
    try:
        os.chmod(filename, 0o600)  # Read/write for owner only
    except OSError:
        print("Warning: Could not set file permissions.  Ensure only the owner can read the file.")


def load_credentials(filename="credentials.dat"):
    """Loads credentials securely and returns username, hashed password, and salt."""
    try:
        with open(filename, "r") as f:
            salt = f.readline().strip()
            hashed_password = f.readline().strip()
            encrypted_username = f.readline().strip()
        return salt, hashed_password, encrypted_username
    except FileNotFoundError:
        return None, None, None

def get_username(password, salt, encrypted_username):
    """Decrypts and returns the username given the password, salt, and encrypted username."""
    encryption_key = generate_encryption_key(password, salt)
    try:
        username = decrypt_data(encrypted_username, encryption_key)
        return username
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# --- Authentication ---

def authenticate_user(username, password, filename="credentials.dat"):
    """Authenticates the user against stored credentials."""
    salt, stored_hash, encrypted_username = load_credentials(filename)

    if salt is None or stored_hash is None or encrypted_username is None:
        print("Credentials not found. Please register first.")
        return False

    if verify_password(password, stored_hash, salt):
        # Verify the username matches the decrypted username
        decrypted_username = get_username(password, salt, encrypted_username)
        if decrypted_username == username:
            print("Authentication successful!")
            return True
        else:
            print("Authentication failed: Username mismatch.")
            return False
    else:
        print("Authentication failed: Incorrect password.")
        return False

# --- Vehicle Array and User Interaction ---

def get_vehicle(vehicles):
    """Prompts the user for a vehicle index and returns the vehicle."""
    while True:
        try:
            index = int(input(f"Enter the index of the vehicle (0-{len(vehicles)-1}): "))
            if 0 <= index < len(vehicles):
                return vehicles[index]
            else:
                print("Invalid index. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def main():
    """Main function to handle user interaction and vehicle access."""

    vehicles = ["Car", "Truck", "Motorcycle", "Bicycle"]

    # --- Registration/Login ---
    filename = "credentials.dat"
    salt, stored_hash, encrypted_username = load_credentials(filename)

    if salt is None or stored_hash is None or encrypted_username is None:
        print("No user registered. Please register now.")
        username = input("Enter a username: ")
        password = getpass("Enter a password: ")  # Secure password input
        store_credentials(username, password, filename)
        print("Registration successful.")
    else:
        username = input("Enter your username: ")
        password = getpass("Enter your password: ")
        if not authenticate_user(username, password, filename):
            return  # Exit if authentication fails

    # --- Access Vehicle Data (Only after successful authentication) ---
    print("\nAvailable Vehicles:")
    for vehicle in vehicles:
        print(vehicle)

    selected_vehicle = get_vehicle(vehicles)
    print(f"You selected: {selected_vehicle}")

if __name__ == "__main__":
    main()

