import boto3
import hashlib
import os
import secrets  # For generating secure random tokens
import time  # For time-based operations
from botocore.config import Config
from botocore.exceptions import ClientError
import re  # For input validation
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)  # Or logging.DEBUG for more detailed logs

# Recommended: Use environment variables or a secure configuration file for sensitive data
# Never hardcode credentials directly in the code.
# Example using environment variables:
# AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
# AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
# AWS_REGION = os.environ.get("AWS_REGION", "us-east-1") # Default region if not set

# Configure boto3 with retry mechanism and timeouts
config = Config(
    retries={'max_attempts': 10},  # Adjust as needed
    connect_timeout=5,  # Seconds
    read_timeout=15  # Seconds
)

# Initialize DynamoDB client (moved outside the function for reuse)
# Ensure proper IAM role/permissions are configured for the Lambda function or application
DYNAMO_CLIENT = boto3.client('dynamodb', config=config)
DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "users") # Use environment variable for table name

# Salt length (adjust as needed)
SALT_LENGTH = 16

# Failed login attempts before lockout
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # Lockout duration in seconds (5 minutes)

# Password reset token expiration time
PASSWORD_RESET_TOKEN_EXPIRATION = 3600  # 1 hour

# Email validation regex
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a randomly generated salt."""
    if salt is None:
        salt = os.urandom(SALT_LENGTH)  # Generate a new random salt
    
    # Use a strong hashing algorithm like SHA256 or SHA512
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100,000 iterations of SHA-256
    )
    return salt, hashed_password

def verify_password(stored_salt, stored_password, provided_password):
    """Verifies the provided password against the stored hash and salt using constant-time comparison."""
    salt = stored_salt
    
    # Hash the provided password using the stored salt
    _, hashed_password = hash_password(provided_password, salt)

    # Compare the generated hash with the stored hash using constant-time comparison
    return secrets.compare_digest(hashed_password, stored_password)

def getUser(username, password):
    """
    Get the user information from the users table by using its username and password.
    Handles authentication securely using password hashing and salting.
    Implements account lockout after multiple failed attempts.
    """
    try:
        response = DYNAMO_CLIENT.get_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={
                'username': {'S': username}
            }
        )

        item = response.get('Item')

        if not item:
            logger.info("User not found: %s", username)
            return None  # User not found

        # Check if the account is locked out
        if 'lockout_end_time' in item:
            lockout_end_time = int(item['lockout_end_time']['N'])
            if lockout_end_time > time.time():
                logger.warning("Account is locked out for user: %s", username)
                return "Account Locked"  # Indicate account is locked

        stored_salt = item.get('salt', {}).get('B')  # Get the stored salt (binary)
        stored_password = item.get('password', {}).get('B')  # Get the stored password hash (binary)

        if not (stored_salt and stored_password):
            logger.error("Authentication failed: Salt or password hash missing for user: %s", username)
            return None  # Authentication failed: Salt or password hash missing

        # Verify the provided password against the stored hash and salt
        if verify_password(stored_salt, stored_password, password):
            # Authentication successful
            logger.info("Authentication successful for user: %s", username)
            # Reset failed login attempts
            update_expression = "SET failed_login_attempts = :zero"
            expression_attribute_values = {":zero": {"N": "0"}}
            DYNAMO_CLIENT.update_item(
                TableName=DYNAMODB_TABLE_NAME,
                Key={'username': {'S': username}},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_attribute_values
            )

            # Remove sensitive information before returning the user data
            user_data = {
                'username': item['username']['S'],
                'email': item.get('email', {}).get('S', None),  # Example: Get email if it exists
                # Add other non-sensitive user data here
            }
            return user_data
        else:
            logger.warning("Authentication failed: Incorrect password for user: %s", username)
            # Increment failed login attempts
            failed_attempts = int(item.get('failed_login_attempts', {}).get('N', '0')) + 1
            update_expression = "SET failed_login_attempts = :attempts"
            expression_attribute_values = {":attempts": {"N": str(failed_attempts)}}

            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                # Lock out the account
                lockout_end_time = int(time.time() + LOCKOUT_DURATION)
                update_expression += ", lockout_end_time = :lockout_time"
                expression_attribute_values[":lockout_time"] = {"N": str(lockout_end_time)}
                logger.warning(f"Account locked out for user: {username}")

            DYNAMO_CLIENT.update_item(
                TableName=DYNAMODB_TABLE_NAME,
                Key={'username': {'S': username}},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_attribute_values
            )
            return None  # Authentication failed: Incorrect password

    except ClientError as e:
        logger.error(f"Error accessing DynamoDB: {e}")
        return None  # Handle DynamoDB errors appropriately


def createUser(username, password, email=None):
    """
    Creates a new user in the DynamoDB table, securely hashing the password.
    Performs input validation.
    """
    # Input validation
    if not validate_input(username, password, email):
        logger.warning("Invalid input for user creation.")
        return False

    # Generate a salt and hash the password
    salt, hashed_password = hash_password(password)

    try:
        item = {
            'username': {'S': username},
            'password': {'B': hashed_password},  # Store the hashed password as binary
            'salt': {'B': salt},  # Store the salt as binary
            'failed_login_attempts': {'N': '0'}  # Initialize failed login attempts
        }
        if email:
            item['email'] = {'S': email}

        DYNAMO_CLIENT.put_item(
            TableName=DYNAMODB_TABLE_NAME,
            Item=item
        )
        logger.info(f"User '{username}' created successfully.")
        return True
    except ClientError as e:
        logger.error(f"Error creating user in DynamoDB: {e}")
        return False

def validate_input(username, password, email=None):
    """Validates username, password, and email."""
    if not (4 <= len(username) <= 50):  # Example length constraints
        logger.warning("Invalid username length.")
        return False
    if not (8 <= len(password) <= 100):  # Example length constraints
        logger.warning("Invalid password length.")
        return False

    if not re.search(r"[A-Z]", password):
        logger.warning("Password must contain at least one uppercase letter.")
        return False
    if not re.search(r"[a-z]", password):
        logger.warning("Password must contain at least one lowercase letter.")
        return False
    if not re.search(r"[0-9]", password):
        logger.warning("Password must contain at least one number.")
        return False
    if not re.search(r"[^a-zA-Z0-9]", password):
        logger.warning("Password must contain at least one special character.")
        return False

    if email and not re.match(EMAIL_REGEX, email):
        logger.warning("Invalid email format.")
        return False
    return True

def hash_token(token):
    """Hashes the password reset token."""
    hashed_token = hashlib.sha256(token.encode('utf-8')).hexdigest()
    return hashed_token

def generate_password_reset_token(username):
    """Generates a unique, time-limited password reset token."""
    token = secrets.token_urlsafe(32)
    expiration_time = int(time.time() + PASSWORD_RESET_TOKEN_EXPIRATION)
    hashed_token = hash_token(token)  # Hash the token before storing

    try:
        DYNAMO_CLIENT.update_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={'username': {'S': username}},
            UpdateExpression="SET password_reset_token = :token, password_reset_token_expiration = :expiration",
            ExpressionAttributeValues={
                ":token": {"S": hashed_token},  # Store the hashed token
                ":expiration": {"N": str(expiration_time)}
            }
        )
        logger.info(f"Password reset token generated for user: {username}")
        return token  # Return the original token to be sent to the user
    except ClientError as e:
        logger.error(f"Error generating password reset token: {e}")
        return None

def verify_password_reset_token(username, token):
    """Verifies the password reset token and returns True if valid, False otherwise."""
    try:
        response = DYNAMO_CLIENT.get_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={'username': {'S': username}},
            ProjectionExpression="password_reset_token, password_reset_token_expiration"
        )
        item = response.get('Item')

        if not item:
            logger.info("User not found during password reset token verification: %s", username)
            return False

        stored_token = item.get('password_reset_token', {}).get('S')
        expiration_time = item.get('password_reset_token_expiration', {}).get('N')

        if not (stored_token and expiration_time):
            logger.warning("Password reset token not found or expired for user: %s", username)
            return False

        expiration_time = int(expiration_time)
        if time.time() > expiration_time:
            logger.warning("Password reset token expired for user: %s", username)
            return False

        hashed_token = hash_token(token)  # Hash the provided token
        if secrets.compare_digest(hashed_token, stored_token):  # Compare the hashed tokens
            logger.info("Password reset token is valid for user: %s", username)
            return True
        else:
            logger.warning("Invalid password reset token for user: %s", username)
            return False

    except ClientError as e:
        logger.error(f"Error verifying password reset token: {e}")
        return False

def reset_password(username, new_password, token):
    """Resets the user's password after verifying the reset token."""
    if not verify_password_reset_token(username, token):
        logger.warning("Invalid or expired password reset token for user: %s", username)
        return False

    # Generate a new salt and hash the new password
    salt, hashed_password = hash_password(new_password)

    try:
        DYNAMO_CLIENT.update_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={'username': {'S': username}},
            UpdateExpression="SET password = :password, salt = :salt, password_reset_token = :null_token, password_reset_token_expiration = :null_expiration",
            ExpressionAttributeValues={
                ":password": {"B": hashed_password},
                ":salt": {"B": salt},
                ":null_token": {"NULL": True},
                ":null_expiration": {"NULL": True}
            }
        )
        logger.info(f"Password reset successfully for user: {username}")
        return True
    except ClientError as e:
        logger.error(f"Error resetting password: {e}")
        return False

# Example usage (for demonstration purposes only - adapt to your application's needs)
if __name__ == '__main__':
    # Example: Create a new user (only run this once for a new user)
    # IMPORTANT:  Never hardcode passwords in your code!  Get them from user input.
    new_username = "testuser"
    new_password = "SecurePassword123!"  # Replace with a strong password from user input
    new_email = "test@example.com"

    if createUser(new_username, new_password, new_email):
        print(f"User '{new_username}' created successfully.")

    # Example: Authenticate an existing user
    username_to_authenticate = "testuser"
    password_to_authenticate = "SecurePassword123!"  # Replace with user-provided password

    user_data = getUser(username_to_authenticate, password_to_authenticate)

    if user_data == "Account Locked":
        print("Account is locked. Please try again later.")
    elif user_data:
        print(f"Authentication successful for user: {user_data['username']}")
        print(f"User email: {user_data.get('email', 'N/A')}") # Access email safely
    else:
        print("Authentication failed.")

    # Example: Generate a password reset token
    reset_token = generate_password_reset_token(new_username)
    if reset_token:
        print(f"Password reset token generated: {reset_token}")

    # Example: Verify a password reset token (replace with the actual token)
    is_token_valid = verify_password_reset_token(new_username, reset_token)
    if is_token_valid:
        print("Password reset token is valid.")

        # Example: Reset the password (replace with the actual token and new password)
        new_reset_password = "NewSecurePassword456!"
        if reset_password(new_username, new_reset_password, reset_token):
            print("Password reset successfully.")
        else:
            print("Password reset failed.")
    else:
        print("Password reset token is invalid.")

