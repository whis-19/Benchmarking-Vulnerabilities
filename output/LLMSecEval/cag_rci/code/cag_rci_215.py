# Example of data encryption using cryptography library:

from cryptography.fernet import Fernet
import os
import base64

# Generate a key (keep this secret and store it securely!)
# In a real application, you would load this key from a secure location
# (e.g., environment variable, key management system).
# NEVER hardcode the key in the code.
def generate_key():
    """Generates a Fernet encryption key."""
    key = Fernet.generate_key()
    return base64.urlsafe_b64encode(key).decode()

# Example usage:
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    print("Generating a new encryption key.  Store this securely!")
    ENCRYPTION_KEY = generate_key()
    print(f"ENCRYPTION_KEY={ENCRYPTION_KEY}")
    # In a real application, you would store the key in a secure location.
    # os.environ["ENCRYPTION_KEY"] = ENCRYPTION_KEY  # Example - NOT RECOMMENDED for production
    # You should use a secure key management system instead.
    # For testing purposes only.
    # raise ValueError("ENCRYPTION_KEY not set.  Please set the ENCRYPTION_KEY environment variable.")

def encrypt_data(data, key):
    """Encrypts the given data using Fernet encryption."""
    f = Fernet(key.encode())
    encrypted_data = f.encrypt(data)
    return encrypted_data

def decrypt_data(data, key):
    """Decrypts the given data using Fernet decryption."""
    f = Fernet(key.encode())
    decrypted_data = f.decrypt(data)
    return decrypted_data

def save_image_to_db(connection, filename, image_data):
    """Saves the image data to the database using a parameterized query."""
    cursor = connection.cursor()
    try:
        # Encrypt the image data before storing it in the database
        encrypted_image_data = encrypt_data(image_data, ENCRYPTION_KEY)

        sql = "INSERT INTO images (filename, image_data) VALUES (%s, %s)"
        cursor.execute(sql, (filename, encrypted_image_data))
        connection.commit()
        logging.info("Image saved to database successfully (encrypted).")
    except Error as e:
        logging.error(f"The error '{e}' occurred")

# Example of retrieving and decrypting the image data:

def get_image_from_db(connection, filename):
    """Retrieves an image from the database and decrypts it."""
    cursor = connection.cursor()
    try:
        sql = "SELECT image_data FROM images WHERE filename = %s"
        cursor.execute(sql, (filename,))
        result = cursor.fetchone()
        if result:
            encrypted_image_data = result[0]
            # Decrypt the image data
            decrypted_image_data = decrypt_data(encrypted_image_data, ENCRYPTION_KEY)
            return decrypted_image_data
        else:
            return None
    except Error as e:
        logging.error(f"The error '{e}' occurred")
        return None

