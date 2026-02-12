from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import bcrypt
import getpass
import time
import logging
import os

def encrypt_with_password(plaintext, password):
    """Encrypts data using AES-GCM with a key derived from a password."""

    # 1. Generate a random salt
    salt = bcrypt.gensalt()  # bcrypt handles salt generation

    # 2. Derive the key using bcrypt
    rounds = 64  # Adjust rounds based on benchmarking
    key = bcrypt.kdf(
        password.encode('utf-8'),  # Password must be bytes-like
        salt=salt,
        desired_key_bytes=32,  # AES-256 key size
        rounds=rounds
    )

    # 3. Generate a random nonce (IV)
    nonce = get_random_bytes(16)

    # 4. Create the AES-GCM cipher object
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # 5. Encrypt the plaintext
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

    # 6. Return the salt, nonce, ciphertext, and tag (or concatenate)
    encrypted_data = salt + nonce + tag + ciphertext
    return encrypted_data


def decrypt_with_password(encrypted_data, password):
    """Decrypts data encrypted with encrypt_with_password."""

    salt = encrypted_data[:bcrypt.SALT_LENGTH]  # Use bcrypt.SALT_LENGTH
    nonce = encrypted_data[bcrypt.SALT_LENGTH:bcrypt.SALT_LENGTH + 16]
    tag = encrypted_data[bcrypt.SALT_LENGTH + 16:bcrypt.SALT_LENGTH + 32]
    ciphertext = encrypted_data[bcrypt.SALT_LENGTH + 32:]

    # 1. Derive the key using bcrypt
    rounds = 64  # Must match the encryption rounds
    key = bcrypt.kdf(
        password.encode('utf-8'),  # Password must be bytes-like
        salt=salt,
        desired_key_bytes=32,  # Must match the encryption key size
        rounds=rounds
    )

    # 2. Create the AES-GCM cipher object
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # 3. Set the authentication tag
    try:
        cipher.verify(tag)  # Raises ValueError if tag is invalid
    except ValueError:
        raise ValueError("Authentication failed: Data may have been tampered with.")

    # 4. Decrypt the ciphertext
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')

    return plaintext


if __name__ == '__main__':
    logging.basicConfig(level=logging.ERROR)  # Configure logging

    password = getpass.getpass("Enter your password: ")  # Get password from user
    plaintext = "This is a secret message."

    # Encryption
    try:
        encrypted_data = encrypt_with_password(plaintext, password)
        print("Encrypted data:", encrypted_data.hex())

        # Store encrypted data to a file (example)
        with open("encrypted_data.bin", "wb") as f:
            f.write(encrypted_data)

    except Exception as e:
        print(f"Encryption failed: {e}")
        exit()

    # Decryption
    try:
        # Load encrypted data from the file (example)
        with open("encrypted_data.bin", "rb") as f:
            loaded_encrypted_data = f.read()

        decrypted_text = decrypt_with_password(loaded_encrypted_data, password)
        print("Decrypted text:", decrypted_text)
        assert plaintext == decrypted_text, "Decryption failed!"
        print("Encryption and decryption successful!")
    except ValueError as e:
        print(f"Decryption failed: Authentication error.  Possible incorrect password or data corruption.")
        logging.error("Decryption failed", exc_info=True)  # Log the full exception
    except FileNotFoundError:
        print("Error: encrypted_data.bin not found.  Did encryption complete successfully?")
    except Exception as e:
        print(f"Decryption failed: {e}")
        logging.error("Decryption failed", exc_info=True)

    # Benchmarking bcrypt.kdf rounds
    password_bytes = "my_secret_password".encode('utf-8')
    salt = bcrypt.gensalt()  # Use gensalt to generate a suitable salt
    desired_key_bytes = 32

    rounds_to_test = [16, 32, 64, 128]  # Test different round values

    print("\nBenchmarking bcrypt.kdf rounds:")
    for rounds in rounds_to_test:
        start_time = time.time()
        key = bcrypt.kdf(password_bytes, salt=salt, desired_key_bytes=desired_key_bytes, rounds=rounds)
        end_time = time.time()
        duration = end_time - start_time
        print(f"Rounds: {rounds}, Key Derivation Time: {duration:.4f} seconds")

    # Clean up the encrypted file
    try:
        os.remove("encrypted_data.bin")
    except FileNotFoundError:
        pass # It's okay if the file doesn't exist

