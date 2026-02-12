import boto3
import os
import hashlib
import hmac
import secrets
import time
from botocore.config import Config

# Configuration for boto3 (retry attempts, etc.)
config = Config(
    retries={
        'max_attempts': 10,
        'mode': 'standard'
    }
)

DYNAMO_CLIENT = boto3.client('dynamodb', config=config)
DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "users")  # Get table name from environment variable

# Salt length for password hashing
SALT_LENGTH = 16

# Number of iterations for PBKDF2-HMAC
PBKDF2_ITERATIONS = 150000

# Rate limiting configuration (adjust as needed)
LOGIN_ATTEMPT_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5

# In-memory rate limiter (replace with a persistent store for production)
login_attempts = {}


def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a randomly generated salt."""
    if salt is None:
        salt = secrets.token_hex(SALT_LENGTH // 2).encode('utf-8')  # Generate a random salt
    else:
        salt = salt.encode('utf-8')

    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS
    )
    return salt.decode('utf-8'), hashed_password.hex()


def verify_password(password, stored_salt, stored_hash):
    """Verifies the password against the stored salt and hash."""
    salt = stored_salt.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(hashed_password.hex(), stored_hash)


def is_rate_limited(username):
    """Checks if the user is rate-limited based on login attempts."""
    now = time.time()
    if username in login_attempts:
        attempts = [t for t in login_attempts[username] if t > now - LOGIN_ATTEMPT_WINDOW]
        login_attempts[username] = attempts
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            return True
    return False


def record_login_attempt(username):
    """Records a login attempt for the given username."""
    now = time.time()
    if username in login_attempts:
        login_attempts[username].append(now)
    else:
        login_attempts[username] = [now]


def get_user(username, password):
    """
    Retrieves user information from DynamoDB and verifies the password.
    Handles rate limiting.
    """

    if is_rate_limited(username):
        return None, "Too many login attempts. Please try again later."

    try:
        response = DYNAMO_CLIENT.get_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={
                'username': {'S': username}
            }
        )

        if 'Item' in response:
            item = response['Item']
            stored_salt = item['salt']['S']
            stored_hash = item['password_hash']['S']

            if verify_password(password, stored_salt, stored_hash):
                # Password is correct
                return item, None  # Return the user item and no error
            else:
                # Incorrect password
                record_login_attempt(username)
                return None, "Incorrect username or password."
        else:
            # User not found
            record_login_attempt(username)
            return None, "Incorrect username or password."

    except Exception as e:
        print(f"Error retrieving user: {e}")
        return None, "An error occurred during authentication."


def create_user(username, password):
    """Creates a new user in DynamoDB with a hashed password."""
    salt, password_hash = hash_password(password)

    try:
        DYNAMO_CLIENT.put_item(
            TableName=DYNAMODB_TABLE_NAME,
            Item={
                'username': {'S': username},
                'salt': {'S': salt},
                'password_hash': {'S': password_hash}
            }
        )
        return True, None
    except Exception as e:
        print(f"Error creating user: {e}")
        return False, str(e)


# Example Usage (for testing - REMOVE in production)
if __name__ == '__main__':
    # Example: Create a user
    new_username = "testuser"
    new_password = "securepassword123"
    success, error = create_user(new_username, new_password)
    if success:
        print(f"User {new_username} created successfully.")
    else:
        print(f"Error creating user: {error}")

    # Example: Authenticate the user
    user, error = get_user(new_username, new_password)
    if user:
        print(f"User {user['username']['S']} authenticated successfully.")
    else:
        print(f"Authentication failed: {error}")

    # Example: Incorrect password
    user, error = get_user(new_username, "wrongpassword")
    if user:
        print(f"User {user['username']['S']} authenticated successfully.")
    else:
        print(f"Authentication failed: {error}")

    # Example: Rate limiting
    for _ in range(MAX_LOGIN_ATTEMPTS + 1):
        get_user(new_username, "wrongpassword")

    user, error = get_user(new_username, new_password)
    if user is None and error == "Too many login attempts. Please try again later.":
        print("Rate limiting is working correctly.")
    else:
        print("Rate limiting is NOT working correctly.")

