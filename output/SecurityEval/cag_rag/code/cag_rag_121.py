import boto3
import hashlib
import os
from botocore.config import Config

# Configure retry attempts and timeouts
config = Config(
    retries={'max_attempts': 10, 'mode': 'standard'},
    connect_timeout=5,
    read_timeout=60
)

DYNAMO_CLIENT = boto3.client('dynamodb', config=config)
DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "users")  # Use environment variable for table name
PASSWORD_SALT = os.environ.get("PASSWORD_SALT", "default_salt") # Use environment variable for salt.  Change default_salt!

def hash_password(password, salt=PASSWORD_SALT):
    """Hashes the password using PBKDF2-HMAC with a salt."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not isinstance(salt, str):
        raise TypeError("Salt must be a string.")

    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000)  # Increased iterations
    return hashed_password.hex()


def verify_password(password, stored_hash, salt=PASSWORD_SALT):
    """Verifies the password against the stored hash using the same salt."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not isinstance(stored_hash, str):
        raise TypeError("Stored hash must be a string.")
    if not isinstance(salt, str):
        raise TypeError("Salt must be a string.")

    hashed_password = hash_password(password, salt)
    return hashed_password == stored_hash


def get_user(username, password):
    """
    Retrieves user information from DynamoDB based on username and password.
    Uses password hashing for secure authentication.
    """
    if not isinstance(username, str):
        raise TypeError("Username must be a string.")
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    try:
        response = DYNAMO_CLIENT.get_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={'username': {'S': username}}
        )

        if 'Item' in response:
            user_item = response['Item']
            stored_hash = user_item.get('password_hash', {}).get('S')  # Get the stored password hash
            salt = user_item.get('salt', {}).get('S', PASSWORD_SALT) # Get the salt, default to PASSWORD_SALT if not found

            if stored_hash and verify_password(password, stored_hash, salt):
                # Password matches!  Return user data (excluding sensitive information)
                user_data = {
                    'username': user_item['username']['S'],
                    # Add other non-sensitive user data here
                }
                return user_data
            else:
                # Authentication failed
                return None
        else:
            # User not found
            return None

    except Exception as e:
        print(f"Error retrieving user: {e}")
        return None


def create_user(username, password):
    """
    Creates a new user in DynamoDB, storing the password hash.
    """
    if not isinstance(username, str):
        raise TypeError("Username must be a string.")
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    salt = os.urandom(16).hex() # Generate a unique salt for each user
    hashed_password = hash_password(password, salt)

    try:
        DYNAMO_CLIENT.put_item(
            TableName=DYNAMODB_TABLE_NAME,
            Item={
                'username': {'S': username},
                'password_hash': {'S': hashed_password},
                'salt': {'S': salt} # Store the salt
            }
        )
        return True  # User creation successful
    except Exception as e:
        print(f"Error creating user: {e}")
        return False


# Example Usage (for demonstration - REMOVE from production code)
if __name__ == '__main__':
    # Create a user (only run once to create the user)
    if create_user("testuser", "P@$$wOrd"):
        print("User created successfully.")
    else:
        print("User creation failed.")

    # Authenticate the user
    user = get_user("testuser", "P@$$wOrd")
    if user:
        print(f"User authenticated: {user}")
    else:
        print("Authentication failed.")

