import os
    import logging
    import tempfile
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    import stat

    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    DEFAULT_KEY_SIZE = 2048
    MIN_KEY_SIZE = int(os.environ.get("MIN_KEY_SIZE", 2048))  # Minimum key size for RSA security
    DEFAULT_KEY_FILE = "my_private_key"

    def create_private_key(key_size=DEFAULT_KEY_SIZE):
        """
        Generates a private key using RSA, exports the key using the OpenSSH format, then returns it.

        Security Considerations:
        - Uses RSA with a key size of 2048 bits or greater (configurable).
        - Leverages the Crypto library for cryptographic operations.
        - Uses Crypto.Random.get_random_bytes for cryptographically secure random number generation.
        - Returns the private key in OpenSSH format, suitable for secure storage and use.

        Args:
            key_size (int): The size of the RSA key to generate (in bits).  Defaults to 2048.  Must be at least 2048 for security.

        Returns:
            str: The private key in OpenSSH format.

        Raises:
            ValueError: If key_size is less than 2048.
        """

        if key_size < MIN_KEY_SIZE:
            raise ValueError(f"Key size must be at least {MIN_KEY_SIZE} bits for security (RSA).")

        try:
            # Generate a new RSA key pair
            key = RSA.generate(key_size, randfunc=get_random_bytes)

            # Export the private key in OpenSSH format
            private_key_pem = key.export_key(format='OpenSSH')

            return private_key_pem.decode('utf-8')  # Decode bytes to string

        except Exception as e:
            logging.error(f"Error generating private key: {e}")
            return None


    def save_private_key(private_key, filename, permissions=0o600):
        """
        Saves the private key to a file with restricted permissions.

        Args:
            private_key (str): The private key in OpenSSH format.
            filename (str): The name of the file to save the key to.
            permissions (int): The file permissions to set (default: 0o600 - owner read/write only).
        """
        try:
            # Sanitize the filename to prevent path traversal attacks
            filename = os.path.abspath(filename)  # Convert to absolute path
            if not filename.startswith(os.getcwd()):  # Ensure it's within the current directory (or a subdirectory)
                raise ValueError("Invalid filename: Path traversal detected.")

            # Ensure the directory exists
            os.makedirs(os.path.dirname(filename), exist_ok=True, mode=0o700)

            # Check parent directory permissions
            parent_dir = os.path.dirname(filename)
            parent_permissions = stat.S_IMODE(os.stat(parent_dir).st_mode)
            if parent_permissions & 0o002:  # Check if world-writable
                logging.warning(f"Parent directory {parent_dir} is world-writable.  This is a security risk.")

            # Store the current umask
            old_umask = os.umask(0o077)  # Set umask to 0o077 temporarily
            try:
                # Use atomic file writing
                with tempfile.NamedTemporaryFile(mode='w', dir=os.path.dirname(filename), delete=False) as tmp_file:
                    tmp_file.write(private_key)
                    temp_filename = tmp_file.name

                # Set file permissions to restrict access
                os.chmod(temp_filename, permissions)

                # Rename the temporary file to the final filename (final step in atomic file writing)
                os.rename(temp_filename, filename)

                logging.info(f"Private key saved to {filename} with permissions {oct(permissions)}")

            finally:
                # Restore the original umask
                os.umask(old_umask)

        except OSError as e:
            logging.error(f"Error saving private key to file: {e}")
            raise  # Re-raise the exception to allow the calling code to handle it.
        except ValueError as e:
            logging.error(f"Invalid filename: {e}")
            raise


    if __name__ == '__main__':
        # Example usage:
        key_file = os.environ.get("RSA_PRIVATE_KEY_FILE", DEFAULT_KEY_FILE)

        private_key = create_private_key()

        if private_key:
            logging.info("Private key generated successfully.")
            #print(private_key) # DO NOT PRINT THE PRIVATE KEY TO THE CONSOLE IN PRODUCTION

            # Save the private key to a file (securely!)
            try:
                save_private_key(private_key, key_file)
            except ValueError as e:
                print(f"Error saving key: {e}")
            private_key = None  # Clear the private key from memory

            # Example of using a larger key size:
            private_key_4096 = create_private_key(key_size=4096)
            if private_key_4096:
                try:
                    save_private_key(private_key_4096, "my_private_key_4096")
                except ValueError as e:
                    print(f"Error saving key: {e}")
                private_key_4096 = None # Clear the private key from memory
        else:
            print("Failed to generate private key.")

