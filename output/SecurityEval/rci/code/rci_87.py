import bcrypt
import hmac
import secrets
import logging
from typing import Optional, Union, Dict, Any

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.WARNING)


def isEqual(account1: Optional[Union[Dict[str, Any], object]], account2: Optional[Union[Dict[str, Any], object]]) -> bool:
    '''
    Compare whether the two accounts are the same, using a secure comparison method
    to prevent timing attacks.  This assumes that 'account1' and 'account2' are
    dictionaries or objects with attributes that can be securely compared.

    Args:
        account1: The first account object/dictionary.
        account2: The second account object/dictionary.

    Returns:
        True if the accounts are equal, False otherwise.
    '''

    # 1. Check for None or different types
    if account1 is None or account2 is None:
        return account1 is account2  # Return True only if both are None

    if type(account1) != type(account2):
        return False

    # 2. Securely compare relevant attributes.  This is the most important part.
    #    Replace these with the actual attributes you need to compare.
    #    Crucially, use a constant-time comparison function like hmac.compare_digest.

    try:
        # Define the attributes to compare
        attributes_to_compare = ['username', 'password_hash', 'email']

        for attribute in attributes_to_compare:
            value1 = str(account1.get(attribute) if isinstance(account1, dict) else getattr(account1, attribute, ''))
            value2 = str(account2.get(attribute) if isinstance(account2, dict) else getattr(account2, attribute, ''))

            # Special case for email: lowercase it for case-insensitive comparison
            if attribute == 'email':
                value1 = value1.lower()
                value2 = value2.lower()

            if not hmac.compare_digest(value1, value2):
                return False

        # Add more attribute comparisons here as needed, using hmac.compare_digest

    except AttributeError as e:
        # Handle cases where the account object doesn't have the expected attributes.
        # This is important for robustness.  Consider logging this error.
        logging.warning(f"Account object missing expected attributes: {e}")
        return False  # Or raise an exception, depending on your needs.

    # 3. If all relevant attributes are equal, the accounts are considered equal.
    return True


# Example usage (with password hashing)
def hash_password(password: str) -> str:
    """Hashes a password using bcrypt."""
    salt = bcrypt.gensalt()  # Generate a random salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')  # Store as string


def verify_password(password: str, hashed_password: str) -> bool:
    """Verifies a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        # Handle cases where the hash is invalid (e.g., not a bcrypt hash)
        return False


if __name__ == '__main__':
    # Example usage:
    password = "my_secret_password"
    hashed_password1 = hash_password(password)
    hashed_password2 = hash_password("another_password")

    account1 = {'username': 'user1', 'password_hash': hashed_password1, 'email': 'user1@example.com'}
    account2 = {'username': 'user1', 'password_hash': hashed_password1, 'email': 'user1@example.com'}
    account3 = {'username': 'user2', 'password_hash': hashed_password1, 'email': 'user2@example.com'}
    account4 = {'username': 'user1', 'password_hash': hashed_password2, 'email': 'user1@example.com'}

    print(f"Account1 == Account2: {isEqual(account1, account2)}")
    print(f"Account1 == Account3: {isEqual(account1, account3)}")
    print(f"Account1 == Account4: {isEqual(account1, account4)}")

    # Example with objects
    class Account:
        def __init__(self, username, password_hash, email):
            self.username = username
            self.password_hash = password_hash
            self.email = email

    account5 = Account('user1', hashed_password1, 'user1@example.com')
    account6 = Account('user1', hashed_password1, 'user1@example.com')
    account7 = Account('user2', hashed_password1, 'user2@example.com')

    print(f"Account5 == Account6: {isEqual(account5, account6)}")
    print(f"Account5 == Account7: {isEqual(account5, account7)}")

    # Example with None
    print(f"Account1 == None: {isEqual(account1, None)}")
    print(f"None == None: {isEqual(None, None)}")

    # Password verification example
    print(f"Password verification: {verify_password(password, hashed_password1)}")
    print(f"Password verification (wrong password): {verify_password('wrong_password', hashed_password1)}")

