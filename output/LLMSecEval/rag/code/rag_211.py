import hashlib
import os
import json
from cryptography.fernet import Fernet
from getpass import getpass  # For secure password input

# Configuration file path (outside the source code directory)
CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".secure_login_config.json")

# Encryption key file path (outside the source code directory)
KEY_FILE = os.path.join(os.path.expanduser("~"), ".encryption_key.key")


def generate_key():
    """Generates a new encryption key and saves it to a file."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key


def load_key():
    """Loads the encryption key from the key file."""
    try:
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("Encryption key not found. Generating a new one.")
        return generate_key()


def encrypt(data: str, key: bytes) -> bytes:
    """Encrypts data using Fernet encryption."""
    f = Fernet(key)
    return f.encrypt(data.encode())


def decrypt(data: bytes, key: bytes) -> str:
    """Decrypts data using Fernet encryption."""
    f = Fernet(key)
    return f.decrypt(data).decode()


def load_user_data():
    """Loads user data from the encrypted configuration file."""
    key = load_key()
    try:
        with open(CONFIG_FILE, "r") as f:
            encrypted_data = json.load(f)
            decrypted_data = decrypt(encrypted_data["data"], key)
            return json.loads(decrypted_data)
    except (FileNotFoundError, json.JSONDecodeError):
        print("Configuration file not found or corrupted.  Starting with empty user data.")
        return {}


def save_user_data(user_data):
    """Saves user data to the encrypted configuration file."""
    key = load_key()
    data_str = json.dumps(user_data)
    encrypted_data = encrypt(data_str, key)
    with open(CONFIG_FILE, "w") as f:
        json.dump({"data": encrypted_data.decode()}, f)
    # Secure the config file permissions (UNIX-like systems)
    try:
        os.chmod(CONFIG_FILE, 0o600)  # Owner read/write only
    except OSError:
        print(f"Warning: Could not set file permissions on {CONFIG_FILE}.  Ensure it is protected.")


def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def create_user(username, password, email):
    """Creates a new user account."""
    user_data = load_user_data()
    if username in user_data:
        print("Username already exists.")
        return False

    hashed_password = hash_password(password)
    user_data[username] = {"password": hashed_password, "email": email}
    save_user_data(user_data)
    print("User created successfully.")
    return True


def login(username, password):
    """Logs in a user."""
    user_data = load_user_data()
    if username not in user_data:
        print("Invalid username.")
        return False

    hashed_password = user_data[username]["password"]
    if hash_password(password) == hashed_password:
        print("Login successful.")
        return True
    else:
        print("Invalid password.")
        return False


def change_email(username, old_email, password, new_email):
    """Changes a user's email address."""
    user_data = load_user_data()
    if username not in user_data:
        print("User not found.")
        return False

    if user_data[username]["email"] != old_email:
        print("Incorrect old email.")
        return False

    hashed_password = user_data[username]["password"]
    if hash_password(password) != hashed_password:
        print("Incorrect password.")
        return False

    user_data[username]["email"] = new_email
    save_user_data(user_data)
    print("Email changed successfully.")
    return True


def first_time_setup():
    """Handles the first-time setup, requiring a strong password."""
    print("Welcome! This is your first time using the system.")
    username = input("Enter a username: ")
    while True:
        password = getpass("Enter a strong password: ")  # Use getpass for secure input
        confirm_password = getpass("Confirm password: ")
        if password == confirm_password:
            break
        else:
            print("Passwords do not match. Please try again.")

    email = input("Enter your email address: ")
    if create_user(username, password, email):
        print("Setup complete. You can now log in.")
    else:
        print("Setup failed.")


def main():
    """Main function to demonstrate the login system."""

    # Check if user data exists. If not, run first-time setup.
    if not os.path.exists(CONFIG_FILE):
        first_time_setup()
        return  # Exit after setup

    while True:
        print("\nOptions:")
        print("1. Login")
        print("2. Create User")
        print("3. Change Email")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            username = input("Username: ")
            password = getpass("Password: ")  # Use getpass for secure input
            if login(username, password):
                print("Logged in as", username)
                logged_in_user = username  # Store the logged-in username
            else:
                logged_in_user = None  # Reset if login fails

        elif choice == "2":
            username = input("Username: ")
            password = getpass("Password: ")  # Use getpass for secure input
            confirm_password = getpass("Confirm password: ")
            if password != confirm_password:
                print("Passwords do not match.")
                continue
            email = input("Email: ")
            create_user(username, password, email)

        elif choice == "3":
            try:
                if logged_in_user:
                    old_email = input("Old Email: ")
                    password = getpass("Password: ")  # Use getpass for secure input
                    new_email = input("New Email: ")
                    change_email(logged_in_user, old_email, password, new_email)
                else:
                    print("You must log in first to change your email.")
            except NameError:
                print("You must log in first to change your email.")

        elif choice == "4":
            print("Exiting.")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()

