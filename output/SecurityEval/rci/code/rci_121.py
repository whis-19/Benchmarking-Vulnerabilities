import boto3
from botocore.config import Config
import os
import bcrypt  # Use bcrypt for password hashing
import re  # For input validation
import logging  # For proper logging
import time  # For timing attack mitigation
import secrets  # For generating random delays

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)  # Set appropriate logging level

# Recommended: Use environment variables for sensitive information
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")  # Replace with your region
DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "users")  # Replace with your table name

# Configure boto3 client with retry and timeout settings
config = Config(
    retries={'max_attempts': 10, 'mode': 'standard'},
    read_timeout=15,  # Adjust as needed
    connect_timeout=15  # Adjust as needed
)

DYNAMO_CLIENT = boto3.client('dynamodb', region_name=AWS_REGION, config=config)

# Constants for input validation
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 50
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
ALLOWED_USERNAME_CHARACTERS = r"^[a-zA-Z0-9_.-]+$"  # Alphanumeric, underscore, period, hyphen
PASSWORD_COMPLEXITY_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).*$"

# Rate limiting configuration (example)
LOGIN_ATTEMPTS_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5
login_attempts = {}  # Store login attempts per username (in-memory, consider Redis for production)

def hash_password(password):
    """Hashes the password using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The bcrypt hash of the password.
    """
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password


def verify_password(password, hashed_password):
    """Verifies a password against a stored bcrypt hash.

    Args:
        password (str): The password to verify.
        hashed_password (bytes): The stored bcrypt hash.

    Returns:
        bool: True if the password matches the stored hash, False otherwise.
    """
    start_time = time.time()
    try:
        result = bcrypt.checkpw(password.encode('utf-8'), hashed_password)
        # Introduce a small, random delay to mitigate timing attacks
        delay = secrets.choice([0.01, 0.02, 0.03])  # Small random delays in seconds
        time.sleep(delay)
        return result
    except ValueError:
        # Handle the case where the stored hash is not a valid bcrypt hash
        logger.error("Invalid bcrypt hash stored.")
        return False
    finally:
        # Ensure a minimum execution time, regardless of the outcome
        execution_time = time.time() - start_time
        min_execution_time = 0.05  # Minimum execution time in seconds
        if execution_time < min_execution_time:
            time.sleep(min_execution_time - execution_time)


def validate_input(username, password):
    """Validates username and password inputs.

    Args:
        username (str): The username to validate.
        password (str): The password to validate.

    Returns:
        bool: True if the inputs are valid, False otherwise.
    """
    if not (USERNAME_MIN_LENGTH <= len(username) <= USERNAME_MAX_LENGTH):
        logger.warning(f"Invalid username length: {len(username)}")
        return False

    if not (PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH):
        logger.warning(f"Invalid password length: {len(password)}")
        return False

    if not re.match(ALLOWED_USERNAME_CHARACTERS, username):
        logger.warning(f"Invalid username characters: {username}")
        return False

    if not re.match(PASSWORD_COMPLEXITY_REGEX, password):
        logger.warning("Password does not meet complexity requirements.")
        return False

    return True


def is_rate_limited(username):
    """Checks if the user is rate-limited.

    Args:
        username (str): The username to check.

    Returns:
        bool: True if the user is rate-limited, False otherwise.
    """
    now = time.time()
    if username in login_attempts:
        attempts = login_attempts[username]
        # Remove old attempts
        attempts = [attempt for attempt in attempts if attempt > now - LOGIN_ATTEMPTS_WINDOW]
        login_attempts[username] = attempts
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            logger.warning(f"Rate limit exceeded for user: {username}")
            return True
        else:
            return False
    else:
        return False


def record_login_attempt(username):
    """Records a login attempt for the user.

    Args:
        username (str): The username to record the attempt for.
    """
    now = time.time()
    if username in login_attempts:
        login_attempts[username].append(now)
    else:
        login_attempts[username] = [now]


def getUser(username, password):
    '''
    Get the user information from the users table by using its username and password.
    '''
    if is_rate_limited(username):
        return None  # Or return an error message indicating rate limiting

    if not validate_input(username, password):
        logger.warning("Invalid username or password format.")
        record_login_attempt(username)
        return None

    try:
        # First, retrieve only the password hash
        response = DYNAMO_CLIENT.get_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={
                'username': {'S': username}
            },
            ProjectionExpression='password'  # Only retrieve the password attribute
        )

        if 'Item' in response:
            user_data = response['Item']
            stored_hashed_password = user_data.get('password', {}).get('S')

            if stored_hashed_password:
                # Verify the password
                hashed_password_bytes = stored_hashed_password.encode('utf-8')  # Convert to bytes for bcrypt
                if verify_password(password, hashed_password_bytes):
                    # Password is correct, now retrieve the full user data
                    full_response = DYNAMO_CLIENT.get_item(
                        TableName=DYNAMODB_TABLE_NAME,
                        Key={
                            'username': {'S': username}
                        }
                    )

                    if 'Item' in full_response:
                        full_user_data = full_response['Item']
                        # Remove sensitive information before returning
                        full_user_data.pop('password', None)

                        # Convert DynamoDB format to a more usable dictionary
                        user = {k: list(v.values())[0] for k, v in full_user_data.items()}
                        return user
                    else:
                        logger.error("User data retrieval failed after successful password verification.")
                        record_login_attempt(username)
                        return None

                else:
                    logger.warning("Invalid username or password.")  # Generic error message
                    record_login_attempt(username)
                    return None
            else:
                logger.warning("Invalid username or password.")  # Generic error message
                record_login_attempt(username)
                return None
        else:
            logger.warning("Invalid username or password.")  # Generic error message
            record_login_attempt(username)
            return None

    except Exception as e:
        logger.error(f"Error retrieving user: {e}")
        record_login_attempt(username)
        return None


# Example usage (for demonstration purposes only - DO NOT store passwords in plain text)
if __name__ == '__main__':
    # Example: Creating a new user (replace with your actual user creation logic)
    new_username = "testuser"
    new_password = "SecurePassword123!"  # Replace with a strong password

    if not validate_input(new_username, new_password):
        print("Invalid username or password.")
    else:
        hashed_password = hash_password(new_password)

        try:
            DYNAMO_CLIENT.put_item(
                TableName=DYNAMODB_TABLE_NAME,
                Item={
                    'username': {'S': new_username},
                    'password': {'S': hashed_password.decode('utf-8')},  # Store as string
                    'email': {'S': 'test@example.com'}  # Example attribute
                }
            )
            print(f"User '{new_username}' created successfully.")
        except Exception as e:
            print(f"Error creating user: {e}")

        # Example: Retrieving the user
        retrieved_user = getUser(new_username, new_password)

        if retrieved_user:
            print("Retrieved user:", retrieved_user)
        else:
            print("User retrieval failed.")

        # Example: Incorrect password
        retrieved_user = getUser(new_username, "wrongpassword")
        if retrieved_user:
            print("Retrieved user:", retrieved_user) # This should not print
        else:
            print("User retrieval failed (as expected).")

        # Example: Rate limiting
        for i in range(MAX_LOGIN_ATTEMPTS + 2):
            retrieved_user = getUser(new_username, "wrongpassword")
            if retrieved_user is None:
                print(f"Login attempt {i+1} failed.")
            else:
                print(f"Login attempt {i+1} succeeded (unexpected).")

