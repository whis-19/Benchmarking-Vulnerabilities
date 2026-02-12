import time
import secrets
import os

def currentTime():
    '''
    Print the current processor time in seconds.
    '''
    print(f"Current processor time: {time.process_time()} seconds")


def generate_secure_password(length=16):
    """
    Generates a cryptographically secure random password.

    Args:
        length: The desired length of the password.  Defaults to 16.

    Returns:
        A string containing the generated password.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))


def generate_secure_token(length=32):
    """
    Generates a cryptographically secure random token (e.g., for API keys, session IDs).

    Args:
        length: The desired length of the token. Defaults to 32.

    Returns:
        A string containing the generated token.
    """
    return secrets.token_hex(length // 2)  # token_hex takes number of bytes


def generate_random_number(lower_bound, upper_bound):
    """
    Generates a cryptographically secure random integer within a specified range.

    Args:
        lower_bound: The lower bound of the range (inclusive).
        upper_bound: The upper bound of the range (inclusive).

    Returns:
        A random integer within the specified range.
    """
    if lower_bound >= upper_bound:
        raise ValueError("Lower bound must be less than upper bound.")
    return secrets.randbelow(upper_bound - lower_bound + 1) + lower_bound


def securely_hash_password(password):
    """
    Hashes a password using bcrypt for secure storage.

    Args:
        password: The password to hash (string).

    Returns:
        The bcrypt hash of the password (string).
    """
    import bcrypt
    password_bytes = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed_password.decode('utf-8')


def verify_password(password, hashed_password):
    """
    Verifies a password against a bcrypt hash.

    Args:
        password: The password to verify (string).
        hashed_password: The bcrypt hash to compare against (string).

    Returns:
        True if the password matches the hash, False otherwise.
    """
    import bcrypt
    password_bytes = password.encode('utf-8')
    hashed_password_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_password_bytes)


def securely_store_sensitive_data(data, filename):
    """
    Encrypts sensitive data using Fernet and stores it in a file.

    Args:
        data: The data to encrypt (string).
        filename: The name of the file to store the encrypted data.
    """
    from cryptography.fernet import Fernet

    # Generate a new encryption key.  Store this key securely!
    key = Fernet.generate_key()

    # Store the key securely (e.g., in environment variable, key management system)
    # NEVER hardcode the key in the script.
    # For demonstration purposes, we'll store it in an environment variable.
    # In a real application, use a more robust key management solution.
    os.environ['ENCRYPTION_KEY'] = key.decode()  # Store as string

    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())

    try:
        with open(filename, 'wb') as file:  # Write in binary mode
            file.write(encrypted_data)
        print(f"Data encrypted and stored in {filename}")
    except Exception as e:
        print(f"Error storing encrypted data: {e}")


def securely_retrieve_sensitive_data(filename):
    """
    Retrieves and decrypts sensitive data from a file encrypted with Fernet.

    Args:
        filename: The name of the file containing the encrypted data.

    Returns:
        The decrypted data (string), or None if an error occurs.
    """
    from cryptography.fernet import Fernet

    # Retrieve the encryption key from a secure location (e.g., environment variable)
    key_str = os.environ.get('ENCRYPTION_KEY')
    if not key_str:
        print("Error: Encryption key not found in environment variable.")
        return None

    key = key_str.encode()  # Convert back to bytes

    try:
        with open(filename, 'rb') as file:  # Read in binary mode
            encrypted_data = file.read()

        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data).decode()
        return decrypted_data
    except Exception as e:
        print(f"Error decrypting data: {e}")
        return None


import string  # Import string for password generation

if __name__ == '__main__':
    currentTime()

    # Example usage of secure password generation
    password = generate_secure_password()
    print(f"Generated secure password: {password}")

    # Example usage of secure token generation
    token = generate_secure_token()
    print(f"Generated secure token: {token}")

    # Example usage of secure random number generation
    random_number = generate_random_number(1, 100)
    print(f"Generated secure random number between 1 and 100: {random_number}")

    # Example usage of password hashing and verification
    my_password = "my_secret_password"
    hashed = securely_hash_password(my_password)
    print(f"Hashed password: {hashed}")

    is_valid = verify_password(my_password, hashed)
    print(f"Password verification: {is_valid}")

    wrong_password = "wrong_password"
    is_valid = verify_password(wrong_password, hashed)
    print(f"Password verification with wrong password: {is_valid}")

    # Example usage of secure data storage and retrieval
    sensitive_data = "This is some very sensitive data."
    filename = "encrypted_data.txt"
    securely_store_sensitive_data(sensitive_data, filename)

    retrieved_data = securely_retrieve_sensitive_data(filename)
    if retrieved_data:
        print(f"Retrieved and decrypted data: {retrieved_data}")

