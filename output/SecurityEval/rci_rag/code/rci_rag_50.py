# ... (previous code)

import certifi  # Add this import
import re

# --- Secure Configuration Handling ---
# ... (previous code)

# --- Example Usage (Illustrative) ---
if __name__ == '__main__':
    # 1. Create a sample encrypted configuration file (replace with your actual logic)
    #    - Store hostname, username, and password in a dictionary.
    #    - Encrypt the dictionary using a strong key derived from a password and salt.
    #    - Save the encrypted data to a file (e.g., 'ftp_config.enc').
    #    - Store the salt and encryption password securely (e.g., environment variables or a secure vault).

    # Example of creating an encrypted config file (DO NOT HARDCODE KEYS/PASSWORDS)
    # This is just for demonstration.  Use a dedicated testing secrets file.
    config_file = "ftp_config.enc"
    hostname = "your_ftp_hostname"
    username = "your_ftp_username"
    password = "your_ftp_password"

    # Generate a random salt (store this securely!)
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt)

    # Set a strong password for encryption (store this securely!)
    encryption_password = "a_very_strong_password"

    # Store the salt and encryption password in a dedicated testing secrets file.
    # THIS FILE IS FOR TESTING ONLY AND SHOULD NEVER BE COMMITTED TO VERSION CONTROL!
    # Add 'test_secrets.txt' to your .gitignore file.
    with open("test_secrets.txt", "w") as f:
        f.write(f"SALT={salt_b64.decode()}\n")
        f.write(f"PASSWORD={encryption_password}\n")

    # Create the data to encrypt
    config_data = f"hostname={hostname}\nusername={username}\npassword={password}"

    # Generate the key
    key = generate_key(encryption_password, salt)

    # Encrypt the data
    encrypted_data = encrypt_data(config_data, key)

    # Write the encrypted data to the config file
    with open(config_file, "wb") as f:
        f.write(encrypted_data)

    # 2. Call the downloadFile function with the path to the encrypted config file
    #    and the name of the sensitive file on the FTP server.
    sensitive_file_to_download = "sensitive_data.txt"
    downloadFile(config_file, sensitive_file_to_download)

# ... (previous code)

def downloadFile(config_file, sensitive_file):
    # ... (previous code)
        import ssl
        import certifi

        ftp = ftplib.FTP_TLS(hostname)
        # VERY IMPORTANT:  Verify the server's certificate to prevent MITM attacks!
        # A CA bundle is a file containing a list of trusted Certificate Authorities (CAs).
        # The server's certificate must be signed by one of these CAs for the connection to be considered secure.
        # Using certifi provides a system-wide CA bundle.
        ftp.context = ssl.create_default_context(cafile=certifi.where())
        ftp.login(username, password)
        logging.info(f"Connected to FTP server: {hostname}")

        # Sanitize the filename to prevent directory traversal and other attacks
        sanitized_filename = os.path.basename(sensitive_file)
        if not re.match(r"^[a-zA-Z0-9_.-]+$", sanitized_filename):
            logging.error(f"Invalid filename: {sensitive_file}. Filename must contain only alphanumeric characters, underscores, hyphens, and periods.")
            return
        local_filepath = sanitized_filename  # Download to current directory

# ... (previous code)

    finally:
        try:
            ftp.quit()
            logging.info("Disconnected from FTP server.")
        except (ftplib.error_perm, ftplib.error_temp) as e:
            logging.warning(f"FTP error during quit (likely already disconnected): {e}")
        except Exception as e:
            logging.error(f"Unexpected error during FTP quit: {e}")

# ... (previous code)

def hash_password(password):
    """Hashes a password using bcrypt (recommended) or Argon2.
    SHA-256 is less secure for password hashing.
    """
    # Example using bcrypt (requires the 'bcrypt' library):
    # pip install bcrypt
    # import bcrypt
    # hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # return hashed_password.decode('utf-8')

    # REMOVED SHA-256 IMPLEMENTATION TO PREVENT ACCIDENTAL MISUSE

# ... (previous code)

