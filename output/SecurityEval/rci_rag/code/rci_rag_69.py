import hashlib
import os
import secrets
import time
import logging
import re  # For input validation example

# Try to import argon2-cffi, but fall back to PBKDF2 if it's not available
try:
    import argon2
    from argon2 import PasswordHasher
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False
    print("argon2-cffi not installed. Falling back to PBKDF2.  Install with: pip install argon2-cffi")


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class PasswordManager:
    """
    Manages password storage, validation, and generation with security best practices.
    """

    def __init__(self, temp_password_expiry=300, pbkdf2_iterations=100000, salt_length=16, password_policy=None, login_attempt_limit=5, lockout_duration=60):  # 5 minutes default expiry
        """
        Initializes the PasswordManager.

        Args:
            temp_password_expiry (int):  Time in seconds for temporary password validity.
            pbkdf2_iterations (int): Number of iterations for PBKDF2HMAC.  Should be increased over time.
            salt_length (int): Length of the salt in bytes.
            password_policy (dict, optional): Dictionary defining password policy rules. Defaults to None.
            login_attempt_limit (int): Number of failed login attempts before lockout.
            lockout_duration (int): Lockout duration in seconds.
        """
        self.temp_passwords = {}  # Store temporary passwords and their expiry timestamps
        self.temp_password_expiry = temp_password_expiry
        self.pbkdf2_iterations = pbkdf2_iterations  # Store the iteration count
        self.salt_length = salt_length  # Store the salt length
        self.password_policy = password_policy if password_policy else {
            'min_length': 8,
            'require_digit': True,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_special': True,
        }
        self.login_attempt_limit = login_attempt_limit
        self.lockout_duration = lockout_duration
        self.login_attempts = {}  # Store login attempts per user (or IP)
        self.password_history = {} # Store password history for each user

    def hash_password(self, password, salt=None):
        """
        Hashes a password using PBKDF2HMAC or Argon2.

        Args:
            password (str): The password to hash.
            salt (bytes, optional):  A salt to use. If None, a new salt is generated.

        Returns:
            tuple: A tuple containing the salt (bytes) and the hashed password (bytes).
        """
        if HAS_ARGON2:
            ph = PasswordHasher()
            hashed_password = ph.hash(password)
            salt = None  # Argon2 doesn't use a separate salt
            return salt, hashed_password.encode('utf-8')  # Store as bytes
        else:
            if salt is None:
                salt = os.urandom(self.salt_length)  # Generate a random salt with configurable length

            hashed_password = hashlib.pbkdf2_hmac(
                'sha256',  # Use SHA256 for hashing
                password.encode('utf-8'),  # Convert password to bytes
                salt,
                self.pbkdf2_iterations  # Use the configured iteration count
            )
            return salt, hashed_password

    def validate_password(self, stored_salt, stored_password, typed_password):
        """
        Validates a password against a stored hash.

        Args:
            stored_salt (bytes): The salt used to hash the stored password.  None for Argon2.
            stored_password (bytes): The stored hashed password.
            typed_password (str): The password entered by the user.

        Returns:
            bool: True if the password is valid, False otherwise.
        """
        if HAS_ARGON2 and stored_salt is None:
            try:
                ph = PasswordHasher()
                return ph.verify(stored_password.decode('utf-8'), typed_password)
            except argon2.exceptions.VerifyMismatchError:
                return False
        else:
            # Hash the typed password using the stored salt
            _, hashed_typed_password = self.hash_password(typed_password, stored_salt)

            # Compare the hashed typed password with the stored password
            return secrets.compare_digest(hashed_typed_password, stored_password)

    def store_temporary_password(self, user_id, password):
        """
        Stores a temporary password.  **IMPORTANT: This implementation is insecure and for demonstration purposes only!**

        Args:
            user_id (str):  Unique identifier for the user.
            password (str): The temporary password to store.
        """
        # INSECURE: Storing in memory.  DO NOT DO THIS IN PRODUCTION!
        # Instead, store in a database or Redis with an expiry.
        # Example (using Redis):
        # self.redis.setex(f"temp_password:{user_id}", self.temp_password_expiry, password)
        # Or, use a signed JWT.
        logging.warning("INSECURE: Storing temporary password in memory.  Use a database or Redis in production!")
        expiry_time = time.time() + self.temp_password_expiry
        self.temp_passwords[user_id] = {'password': password, 'expiry': expiry_time}

    def validate_temporary_password(self, user_id, typed_password):
        """
        Validates a temporary password.  **IMPORTANT: This implementation is insecure and for demonstration purposes only!**

        Args:
            user_id (str): Unique identifier for the user.
            typed_password (str): The password entered by the user.

        Returns:
            bool: True if the temporary password is valid and not expired, False otherwise.
        """
        # INSECURE: Retrieving from memory.  DO NOT DO THIS IN PRODUCTION!
        # Instead, retrieve from the database or Redis.
        # Example (using Redis):
        # stored_password = self.redis.get(f"temp_password:{user_id}")
        # if stored_password and secrets.compare_digest(stored_password.decode(), typed_password):
        #     self.redis.delete(f"temp_password:{user_id}")
        #     return True
        # return False
        if user_id in self.temp_passwords:
            temp_password_data = self.temp_passwords[user_id]
            if time.time() <= temp_password_data['expiry'] and secrets.compare_digest(temp_password_data['password'], typed_password):
                del self.temp_passwords[user_id]  # Remove the temporary password after successful validation
                logging.info(f"Temporary password validated and removed for user: {user_id}")
                return True
            else:
                # Password expired or incorrect
                logging.warning(f"Temporary password validation failed for user: {user_id}")
                return False
        else:
            # No temporary password found for this user
            logging.warning(f"No temporary password found for user: {user_id}")
            return False

    def generate_and_store_initial_password(self, user_id, password_length=20):
        """
        Generates a strong initial password, hashes it, and stores the salt and hash.
        This simulates the "first login" scenario.

        Args:
            user_id (str): Unique identifier for the user.
            password_length (int): Length of the initial password.

        Returns:
            tuple: (salt, hashed_password, initial_password)
        """
        initial_password = self.generate_temporary_password(password_length) # Use generate_temporary_password for strong initial password
        salt, hashed_password = self.hash_password(initial_password)
        # In a real application, you would store the salt and hashed_password
        # in a database associated with the user_id.
        # For example:
        # self.db.store_user_credentials(user_id, salt, hashed_password)
        logging.info(f"Initial password generated for user: {user_id}")
        return salt, hashed_password, initial_password

    def enforce_password_policy(self, password):
        """
        Enforces a password policy based on the configured rules.

        Args:
            password (str): The password to validate.

        Returns:
            bool: True if the password meets the policy, False otherwise.
        """
        if len(password) < self.password_policy['min_length']:
            return False  # Minimum length requirement
        if self.password_policy['require_digit'] and not any(char.isdigit() for char in password):
            return False  # Requires at least one digit
        if self.password_policy['require_uppercase'] and not any(char.isupper() for char in password):
            return False  # Requires at least one uppercase letter
        if self.password_policy['require_lowercase'] and not any(char.islower() for char in password):
            return False  # Requires at least one lowercase letter
        if self.password_policy['require_special'] and not any(char in "!@#$%^&*()" for char in password):
            return False  # Requires at least one special character
        return True

    def check_password_history(self, user_id, new_password):
        """
        Checks if the new password is in the user's password history.

        Args:
            user_id (str): Unique identifier for the user.
            new_password (str): The new password to check.

        Returns:
            bool: True if the password is in the history, False otherwise.
        """
        # INSECURE: Storing password history in memory.  Use a database.
        if user_id in self.password_history:
            for salt, hashed_password in self.password_history[user_id]:
                if self.validate_password(salt, hashed_password, new_password):
                    return True
        return False

    def update_password(self, user_id, new_password):
        """
        Updates the user's password, storing the new hash and salt, and adding the old password to the history.

        Args:
            user_id (str): Unique identifier for the user.
            new_password (str): The new password.

        Returns:
            tuple: (salt, hashed_password) of the new password.  Returns None if password policy is not met or password is in history.
        """

        # Input validation example:  Check if user_id is a valid format
        if not re.match(r"^[a-zA-Z0-9_]+$", user_id):  # Example: alphanumeric and underscore only
            logging.warning(f"Invalid user_id format: {user_id}")
            return None

        if not self.enforce_password_policy(new_password):
            logging.warning(f"Password policy not met for user: {user_id}")
            return None

        if self.check_password_history(user_id, new_password):
            logging.warning(f"Password in history for user: {user_id}")
            return None

        salt, hashed_password = self.hash_password(new_password)

        # Store the old password in the history
        # INSECURE: Storing password history in memory.  Use a database.
        if user_id not in self.password_history:
            self.password_history[user_id] = []
        # Limit the password history to a reasonable size (e.g., 5)
        self.password_history[user_id] = [(salt, hashed_password)] + self.password_history[user_id][:4]

        logging.info(f"Password updated for user: {user_id}")
        return salt, hashed_password

    def record_login_attempt(self, user_id, ip_address):
        """
        Records a login attempt (successful or failed) for a user or IP address.

        Args:
            user_id (str): Unique identifier for the user.
            ip_address (str): IP address of the user.
        """
        # INSECURE: Storing login attempts in memory.  Use a database or Redis.
        key = user_id if user_id else ip_address  # Prioritize user_id if available
        now = time.time()

        if key not in self.login_attempts:
            self.login_attempts[key] = []

        # Remove old attempts
        self.login_attempts[key] = [attempt for attempt in self.login_attempts[key] if attempt > now - self.lockout_duration]

        self.login_attempts[key].append(now)

        logging.info(f"Login attempt recorded for key: {key}")

    def is_locked_out(self, user_id, ip_address):
        """
        Checks if a user or IP address is locked out due to too many failed login attempts.

        Args:
            user_id (str): Unique identifier for the user.
            ip_address (str): IP address of the user.

        Returns:
            bool: True if the user/IP is locked out, False otherwise.
        """
        # INSECURE: Retrieving login attempts from memory.  Use a database or Redis.
        key = user_id if user_id else ip_address
        if key in self.login_attempts:
            num_attempts = len(self.login_attempts[key])
            if num_attempts >= self.login_attempt_limit:
                logging.warning(f"Account locked out for key: {key}")
                return True
        return False

    def login(self, user_id, password, stored_salt, stored_password, ip_address):
        """
        Authenticates a user.

        Args:
            user_id (str): Unique identifier for the user.
            password (str): The password entered by the user.
            stored_salt (bytes): The stored salt for the user.
            stored_password (bytes): The stored hashed password for the user.
            ip_address (str): IP address of the user.

        Returns:
            bool: True if login is successful, False otherwise.
        """
        if self.is_locked_out(user_id, ip_address):
            logging.warning(f"Login attempt blocked for locked out key: {user_id if user_id else ip_address}")
            return False

        if self.validate_password(stored_salt, stored_password, password):
            self.record_login_attempt(user_id, ip_address)  # Record successful attempt (optional)
            logging.info(f"Login successful for user: {user_id}")
            return True
        else:
            self.record_login_attempt(user_id, ip_address)
            logging.warning(f"Login failed for user: {user_id}")
            return False


# Example Usage (Illustrative - Adapt to your specific application)
if __name__ == '__main__':
    # Example configuration
    password_policy = {
        'min_length': 10,
        'require_digit': True,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_special': True,
    }

    password_manager = PasswordManager(pbkdf2_iterations=200000, salt_length=32, password_policy=password_policy, login_attempt_limit=3, lockout_duration=120)

    # 1. First Login Scenario
    user_id = "new_user123"
    salt, hashed_password, initial_password = password_manager.generate_and_store_initial_password(user_id)
    print(f"Initial Password for {user_id}: {initial_password}")
    print("Store the salt and hashed password securely in your database.")

    # 2. User changes password after first login
    new_password = "StrongerPassword123!"
    updated_credentials = password_manager.update_password(user_id, new_password)
    if updated_credentials:
        new_salt, new_hashed_password = updated_credentials
        print("New password meets policy.  Store the new_salt and new_hashed_password securely.")
        # Replace the old salt and hashed password in the database with the new ones.
    else:
        print("New password does not meet the password policy or is in history.  Prompt user to choose a stronger password.")

    # 3. Validation Example
    typed_password = "StrongerPassword123!"
    is_valid = password_manager.validate_password(new_salt, new_hashed_password, typed_password)
    print(f"Password validation result: {is_valid}")

    # 4. Temporary Password Example
    temp_password = password_manager.generate_temporary_password()
    password_manager.store_temporary_password("user456", temp_password)
    print(f"Temporary password generated and stored: {temp_password}")

    # Simulate user entering the temporary password
    entered_temp_password = temp_password
    is_temp_valid = password_manager.validate_temporary_password("user456", entered_temp_password)
    print(f"Temporary password validation result: {is_temp_valid}")

    # Attempt to use the temporary password again (should fail because it's been removed)
    is_temp_valid_again = password_manager.validate_temporary_password("user456", entered_temp_password)
    print(f"Temporary password validation result (again): {is_temp_valid_again}")

    # 5. Login Example with Rate Limiting and Lockout
    ip_address = "192.168.1.1"
    for i in range(5):
        login_success = password_manager.login(user_id, "wrong_password", new_salt, new_hashed_password, ip_address)
        print(f"Login attempt {i+1}: {login_success}")
        if password_manager.is_locked_out(user_id, ip_address):
            print("Account locked out.  Please try again later.")
            break

    # Simulate a successful login after lockout period
    time.sleep(password_manager.lockout_duration + 1)
    login_success = password_manager.login(user_id, typed_password, new_salt, new_hashed_password, ip_address)
    print(f"Login attempt after lockout: {login_success}")

