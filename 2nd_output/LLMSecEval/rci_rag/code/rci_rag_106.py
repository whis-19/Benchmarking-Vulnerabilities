import os
import stat
import secrets  # For cryptographically secure random numbers
import hashlib # For hashing example
import base64 # For encoding example

def create_and_secure_file(filename="secret.txt", content=""):  # Changed default content to empty string
    """
    Creates a file with sensitive content and restricts its permissions.

    Args:
        filename (str): The name of the file to create. Defaults to "secret.txt".
        content (str): The content to write to the file. Defaults to "".
                     It's generally best to avoid default content for security reasons.
    """

    try:
        # Write the content to the file
        with open(filename, "w") as f:
            f.write(content)

        # Restrict file permissions to owner read/write only (0o600)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)  # Equivalent to 0o600

        print(f"File '{filename}' created and permissions restricted successfully.")

    except OSError as e:
        print(f"Error creating or securing file: {e}")


def secure_delete_file(filename, passes=3):
    """Securely deletes a file by overwriting it multiple times.

    Note: This method is most effective on traditional spinning hard drives.
    On SSDs (Solid State Drives), wear-leveling algorithms can make it
    difficult to guarantee complete data erasure.
    """
    try:
        file_size = os.path.getsize(filename)
        with open(filename, "wb") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(file_size))  # Use secrets for random data
        os.remove(filename)
        print(f"File '{filename}' securely deleted.")
    except OSError as e:
        print(f"Error securely deleting file: {e}")


if __name__ == "__main__":
    create_and_secure_file()
    # Example of secure deletion (after the file is no longer needed)
    secure_delete_file("secret.txt")

    # Example of hashing a password (not directly related to file creation, but important)
    password = "my_secret_password"
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password  # Prepend the salt to the password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    print(f"Salted and hashed password: {hashed_password}")
    print(f"Salt: {salt}") # Store the salt along with the hashed password (e.g., in the database)

    # Example of encoding data (not encryption!)
    data = "Sensitive data"
    encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')
    print(f"Encoded data: {encoded_data}")
    print("Encoding is not encryption! It simply transforms data into a different format, but it doesn't provide any confidentiality. Anyone with the encoding algorithm can easily decode the data.")


    # Example of using static analysis (Bandit) - run this from the command line: bandit -r .
    # This is just a comment, Bandit needs to be run separately.

