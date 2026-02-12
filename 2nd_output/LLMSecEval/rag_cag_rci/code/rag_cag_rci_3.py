import os
import hashlib
import secrets
import base64
from getpass import getpass  # For secure password input
from cryptography.fernet import Fernet
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class AuthenticationError(Exception):
    """Custom exception for authentication failures."""
    pass


class CredentialManager:
    """Manages user credentials securely."""

    def __init__(self, credentials_file="credentials.dat", encryption_key_file="encryption.key"):
        self.credentials_file = credentials_file
        self.encryption_key_file = encryption_key_file
        self.fernet = self._load_fernet()
        self.users = self._load_users()
        self.rate_limit = {}  # Dictionary to store login attempt counts per user
        self.max_attempts = 3  # Maximum number of login attempts allowed
        self.lockout_time = 60  # Lockout time in seconds

    def _generate_encryption_key(self):
        """Generates a new encryption key and saves it to a file."""
        key = Fernet.generate_key()
        with open(self.encryption_key_file, "wb") as key_file:
            key_file.write(key)
        return key

    def _load_fernet(self):
        """Loads the Fernet encryption key from a file or generates a new one if it doesn't exist."""
        try:
            with open(self.encryption_key_file, "rb") as key_file:
                key = key_file.read()
        except FileNotFoundError:
            key = self._generate_encryption_key()
        return Fernet(key)

    def _load_users(self):
        """Loads user credentials from the encrypted file."""
        users = {}
        try:
            with open(self.credentials_file, "rb") as f:
                encrypted_data = f.read()
                decrypted_data = self.fernet.decrypt(encrypted_data).decode()
                for line in decrypted_data.splitlines():
                    username, salt, hashed_password = line.split(":")
                    users[username] = {"salt": salt, "hashed_password": hashed_password}
        except FileNotFoundError:
            logging.warning("Credentials file not found.  No users loaded.")
        except Exception as e:
            logging.error(f"Error loading users: {e}")
        return users

    def _save_users(self):
        """Saves user credentials to the encrypted file."""
        data_to_encrypt = ""
        for username, user_data in self.users.items():
            data_to_encrypt += f"{username}:{user_data['salt']}:{user_data['hashed_password']}\n"

        encrypted_data = self.fernet.encrypt(data_to_encrypt.encode())
        with open(self.credentials_file, "wb") as f:
            f.write(encrypted_data)

    def register_user(self, username, password):
        """Registers a new user, hashing the password and storing it securely."""
        if username in self.users:
            raise ValueError("Username already exists.")

        salt = secrets.token_hex(16)  # Generate a random salt
        hashed_password = self._hash_password(password, salt)
        self.users[username] = {"salt": salt, "hashed_password": hashed_password}
        self._save_users()
        logging.info(f"User {username} registered successfully.")

    def _hash_password(self, password, salt):
        """Hashes the password using PBKDF2-HMAC with a salt."""
        salted_password = salt.encode() + password.encode()
        hashed_password = hashlib.pbkdf2_hmac(
            "sha256",
            salted_password,
            salt.encode(),
            100000  # Number of iterations - adjust for security/performance tradeoff
        )
        return base64.b64encode(hashed_password).decode()

    def authenticate_user(self, username, password):
        """Authenticates a user by verifying the password against the stored hash."""
        if username not in self.users:
            raise AuthenticationError("Invalid username or password.")

        if self.is_rate_limited(username):
            raise AuthenticationError("Too many login attempts. Account locked.")

        user_data = self.users[username]
        salt = user_data["salt"]
        stored_hashed_password = user_data["hashed_password"]

        hashed_password = self._hash_password(password, salt)

        if hashed_password == stored_hashed_password:
            logging.info(f"User {username} authenticated successfully.")
            self.reset_rate_limit(username)  # Reset rate limit on successful login
            return True
        else:
            self.increment_rate_limit(username)
            logging.warning(f"Authentication failed for user {username}.")
            raise AuthenticationError("Invalid username or password.")

    def increment_rate_limit(self, username):
        """Increments the login attempt count for a user."""
        if username not in self.rate_limit:
            self.rate_limit[username] = {"attempts": 0, "lockout_time": 0}
        self.rate_limit[username]["attempts"] += 1
        logging.info(f"Login attempt for {username}. Attempts: {self.rate_limit[username]['attempts']}")

        if self.rate_limit[username]["attempts"] >= self.max_attempts:
            self.rate_limit[username]["lockout_time"] = time.time() + self.lockout_time
            logging.warning(f"Account locked for user {username}.")

    def reset_rate_limit(self, username):
        """Resets the login attempt count for a user."""
        if username in self.rate_limit:
            del self.rate_limit[username]

    def is_rate_limited(self, username):
        """Checks if a user is rate limited."""
        if username in self.rate_limit:
            if self.rate_limit[username]["lockout_time"] > time.time():
                return True
        return False


import time

def main():
    """Main function to demonstrate the vehicle array and authentication."""

    credential_manager = CredentialManager()

    # Example: Register a new user (only if no users exist)
    if not credential_manager.users:
        try:
            new_username = input("Enter a username to register: ")
            new_password = getpass("Enter a password for the new user: ")  # Secure password input
            credential_manager.register_user(new_username, new_password)
            print("User registered successfully.")
        except ValueError as e:
            print(f"Error registering user: {e}")
            return

    # Authentication
    try:
        username = input("Enter your username: ")
        password = getpass("Enter your password: ")  # Secure password input
        credential_manager.authenticate_user(username, password)
        print("Authentication successful!")
    except AuthenticationError as e:
        print(f"Authentication failed: {e}")
        return

    # Vehicle array and user interaction (only after successful authentication)
    vehicles = ["car", "truck", "motorcycle", "bicycle"]

    while True:
        try:
            index = int(input(f"Enter the index of a vehicle (0-{len(vehicles)-1}): "))
            if 0 <= index < len(vehicles):
                print(f"Vehicle at index {index}: {vehicles[index]}")
                break  # Exit the loop after a valid index is entered
            else:
                print("Invalid index. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            break

    print("\nAll vehicles:")
    for vehicle in vehicles:
        print(vehicle)


if __name__ == "__main__":
    main()

