import boto3
import hashlib
import os
from botocore.config import Config
from botocore.exceptions import ClientError

# Recommended: Use environment variables or a secure configuration file for sensitive data
# Never hardcode credentials directly in the code.
DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "users")  # Default table name
# Configure retry attempts and timeouts
config = Config(
    retries={'max_attempts': 10},
    connect_timeout=5,
    read_timeout=15
)

DYNAMO_CLIENT = boto3.client('dynamodb', config=config)


def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """Hashes the password using PBKDF2HMAC with a randomly generated salt.

    Args:
        password: The password to hash.
        salt: Optional salt to use. If None, a new salt is generated.

    Returns:
        A tuple containing the hexadecimal representation of the salt and the hashed password.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Use PBKDF2HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for the hash function
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed for security vs. performance)
    )
    return salt.hex(), hashed_password.hex()


def verify_password(password: str, salt_hex: str, hashed_password_hex: str) -> bool:
    """Verifies the password against the stored hash and salt.

    Args:
        password: The password to verify.
        salt_hex: The hexadecimal representation of the salt.
        hashed_password_hex: The hexadecimal representation of the stored hashed password.

    Returns:
        True if the password matches the stored hash, False otherwise.
    """
    try:
        salt = bytes.fromhex(salt_hex)
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        return hashed_password.hex() == hashed_password_hex
    except ValueError:
        # Handle potential errors if salt or hash are invalid hex strings
        return False


def get_user(username: str, password: str) -> dict | None:
    """
    Retrieves user information from DynamoDB based on username and password.

    Args:
        username: The username of the user.
        password: The password of the user.

    Returns:
        A dictionary containing the user information if found and the password matches,
        None otherwise.
    """
    try:
        response = DYNAMO_CLIENT.get_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={'username': {'S': username}}
        )

        item = response.get('Item')

        if item:
            stored_salt_hex = item.get('salt', {}).get('S')
            stored_hashed_password_hex = item.get('hashed_password', {}).get('S')

            if stored_salt_hex and stored_hashed_password_hex:
                if verify_password(password, stored_salt_hex, stored_hashed_password_hex):
                    # Password matches!  Remove sensitive data before returning
                    user_data = {k: v for k, v in item.items() if k not in ('salt', 'hashed_password')}
                    # Convert DynamoDB types to Python types
                    user_data = {k: list(v.values())[0] for k, v in user_data.items()}
                    return user_data
                else:
                    print("Incorrect password for user:", username)
                    return None
            else:
                print("User found, but password information is incomplete for user:", username)
                return None
        else:
            print("User not found:", username)
            return None

    except ClientError as e:
        print(f"Error retrieving user: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def create_user(username: str, password: str) -> bool:
    """
    Creates a new user in DynamoDB with a hashed password.

    Args:
        username: The username of the new user.
        password: The password of the new user.

    Returns:
        True if the user was created successfully, False otherwise.
    """
    try:
        salt_hex, hashed_password_hex = hash_password(password)

        DYNAMO_CLIENT.put_item(
            TableName=DYNAMODB_TABLE_NAME,
            Item={
                'username': {'S': username},
                'salt': {'S': salt_hex},
                'hashed_password': {'S': hashed_password_hex},
                # Add other user attributes here as needed
            },
            ConditionExpression='attribute_not_exists(username)'  # Prevent overwriting existing users
        )
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            print(f"User with username '{username}' already exists.")
        else:
            print(f"Error creating user: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


def first_login_setup(username: str, new_password: str) -> bool:
    """
    Handles the first login setup, requiring a unique strong password.

    Args:
        username: The username of the user.
        new_password: The new, strong password to set.

    Returns:
        True if the password was successfully updated, False otherwise.
    """
    # Check if the user exists and has not yet set a password (e.g., 'salt' attribute is missing)
    try:
        response = DYNAMO_CLIENT.get_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={'username': {'S': username}}
        )

        item = response.get('Item')

        if item and 'salt' not in item:  # Check if salt exists, indicating password already set
            # Hash the new password
            salt_hex, hashed_password_hex = hash_password(new_password)

            # Update the user item with the hashed password and salt
            DYNAMO_CLIENT.update_item(
                TableName=DYNAMODB_TABLE_NAME,
                Key={'username': {'S': username}},
                UpdateExpression='SET salt = :salt, hashed_password = :hashed_password',
                ExpressionAttributeValues={
                    ':salt': {'S': salt_hex},
                    ':hashed_password': {'S': hashed_password_hex}
                }
            )
            return True
        else:
            print("User not found or password already set.")
            return False

    except ClientError as e:
        print(f"Error during first login setup: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


# Example Usage (for demonstration purposes only - adapt to your application)
if __name__ == '__main__':
    # Example: Create a new user
    new_username = "testuser"
    new_password = "P@$$wOrd"  # Replace with a strong password
    if create_user(new_username, new_password):
        print(f"User '{new_username}' created successfully.")

    # Example: Get user information
    user = get_user(new_username, new_password)
    if user:
        print("User information:", user)
    else:
        print("User not found or incorrect password.")

    # Example: First login setup (if needed)
    first_login_username = "newuser"  # A user created without a password initially
    first_login_password = "StrongPassword123!"
    # Create the user without password first
    if create_user(first_login_username, ""):
        print(f"User '{first_login_username}' created successfully.")
    if first_login_setup(first_login_username, first_login_password):
        print(f"First login setup successful for user '{first_login_username}'.")
    else:
        print(f"First login setup failed for user '{first_login_username}'.")

