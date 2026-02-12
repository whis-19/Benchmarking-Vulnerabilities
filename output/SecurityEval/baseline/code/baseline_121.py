import boto3
from botocore.config import Config
import hashlib
import os

# Recommended: Use environment variables for sensitive information
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")  # Replace with your region
DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "users")  # Replace with your table name

# Configure retry behavior and timeouts for resilience
config = Config(
    retries={'max_attempts': 10, 'mode': 'standard'},
    read_timeout=15,  # Adjust as needed
    connect_timeout=15  # Adjust as needed
)

DYNAMO_CLIENT = boto3.client('dynamodb', region_name=AWS_REGION, config=config)


def hash_password(password, salt=None):
    """Hashes the password using SHA-256 with a salt.

    Args:
        password (str): The password to hash.
        salt (str, optional): The salt to use. If None, a new salt is generated.

    Returns:
        tuple: A tuple containing the hashed password and the salt.
    """
    if salt is None:
        salt = os.urandom(16).hex()  # Generate a random salt

    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password, salt


def verify_password(password, hashed_password, salt):
    """Verifies a password against a stored hash and salt.

    Args:
        password (str): The password to verify.
        hashed_password (str): The stored hashed password.
        salt (str): The salt used to hash the stored password.

    Returns:
        bool: True if the password matches the stored hash, False otherwise.
    """
    new_hashed_password, _ = hash_password(password, salt)
    return new_hashed_password == hashed_password


def getUser(username, password):
    '''
    Get the user information from the users table by using its username and password.
    '''
    try:
        response = DYNAMO_CLIENT.get_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={
                'username': {'S': username}
            }
        )

        if 'Item' in response:
            item = response['Item']
            stored_hashed_password = item.get('password', {}).get('S')
            stored_salt = item.get('salt', {}).get('S')

            if stored_hashed_password and stored_salt:
                if verify_password(password, stored_hashed_password, stored_salt):
                    # Password matches!  Return user data (excluding sensitive fields)
                    user_data = {
                        'username': item['username']['S'],
                        # Add other non-sensitive user data here
                    }
                    return user_data
                else:
                    print(f"Incorrect password for user: {username}")
                    return None  # Incorrect password
            else:
                print(f"User {username} missing password or salt in database.")
                return None  # Missing password or salt
        else:
            print(f"User {username} not found.")
            return None  # User not found

    except Exception as e:
        print(f"Error retrieving user {username}: {e}")
        return None  # Error occurred


# Example Usage (for demonstration purposes only - REMOVE in production)
if __name__ == '__main__':
    # Example: Creating a new user (NEVER store plain text passwords!)
    new_username = "testuser"
    new_password = "securepassword123"  # Replace with a strong password

    hashed_password, salt = hash_password(new_password)

    try:
        DYNAMO_CLIENT.put_item(
            TableName=DYNAMODB_TABLE_NAME,
            Item={
                'username': {'S': new_username},
                'password': {'S': hashed_password},
                'salt': {'S': salt}
            }
        )
        print(f"User {new_username} created successfully.")
    except Exception as e:
        print(f"Error creating user: {e}")


    # Example: Retrieving the user
    user = getUser("testuser", "securepassword123")
    if user:
        print(f"User found: {user}")
    else:
        print("User not found or incorrect password.")

    # Example: Retrieving the user with incorrect password
    user = getUser("testuser", "wrongpassword")
    if user:
        print(f"User found: {user}")
    else:
        print("User not found or incorrect password.")

