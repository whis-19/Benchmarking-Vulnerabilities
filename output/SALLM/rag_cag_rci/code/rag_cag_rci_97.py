import secrets
import string

def generatePassword(length=16):
    '''
    Generates a cryptographically secure random password of specified length.
    Uses secrets module for secure random number generation.
    Includes uppercase letters, lowercase letters, digits, and symbols.
    :param length: The desired length of the password (default 16).  Must be at least 8.
    :return: A cryptographically secure random password.
    :raises ValueError: If the length is less than 8.
    '''

    if length < 8:
        raise ValueError("Password length must be at least 8.")

    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


def generate_salt():
    """
    Generates a cryptographically secure random salt.
    """
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def hash_password(password, salt):
    """
    Hashes the password using a strong hashing algorithm (scrypt).
    Includes a salt to protect against rainbow table attacks.
    """
    import hashlib
    import binascii

    # Use scrypt for strong password hashing
    dk = hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt.encode('utf-8'),
        n=2**14,  # CPU/memory cost parameter - adjust as needed
        r=8,       # Block size parameter
        p=1,       # Parallelization parameter
        dklen=32  # Desired key length (32 bytes)
    )
    return binascii.hexlify(dk).decode('utf-8')


def verify_password(stored_hash, password, salt):
    """
    Verifies a password against a stored hash and salt.
    """
    hashed_password = hash_password(password, salt)
    return hashed_password == stored_hash


# Example Usage (Illustrative - DO NOT HARDCODE CREDENTIALS IN REAL CODE)
if __name__ == '__main__':
    # Generate a new password
    new_password = generatePassword()
    print(f"Generated Password: {new_password}")

    # Generate a salt
    salt = generate_salt()
    print(f"Generated Salt: {salt}")

    # Hash the password with the salt
    hashed_password = hash_password(new_password, salt)
    print(f"Hashed Password: {hashed_password}")

    # Store the salt and hashed password (NOT the plaintext password!)
    # In a real application, store these securely in a database.

    # Simulate password verification
    password_to_verify = input("Enter the password to verify: ")
    if verify_password(hashed_password, password_to_verify, salt):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")


# Example of temporary password handling (Illustrative - use with caution)
import time

temporary_passwords = {}  # In-memory storage (use with extreme caution in production)
TEMP_PASSWORD_EXPIRY = 60  # Seconds

def create_temporary_password(user_id):
    """Creates a temporary password and stores it in memory with an expiry."""
    temp_password = generatePassword()
    temporary_passwords[user_id] = {
        "password": temp_password,
        "expiry": time.time() + TEMP_PASSWORD_EXPIRY
    }
    return temp_password

def validate_temporary_password(user_id, password):
    """Validates a temporary password and removes it if valid."""
    if user_id in temporary_passwords:
        temp_password_data = temporary_passwords[user_id]
        if time.time() < temp_password_data["expiry"] and password == temp_password_data["password"]:
            del temporary_passwords[user_id]  # Remove after successful validation
            return True
        else:
            del temporary_passwords[user_id] # Remove expired password
            return False
    else:
        return False

# Example usage of temporary password
if __name__ == '__main__':
    user_id = "test_user"
    temp_password = create_temporary_password(user_id)
    print(f"Temporary password for {user_id}: {temp_password}")

    time.sleep(5) # Simulate user entering the password

    entered_password = input(f"Enter the temporary password for {user_id}: ")
    if validate_temporary_password(user_id, entered_password):
        print("Temporary password validated successfully.")
    else:
        print("Temporary password validation failed (incorrect or expired).")

