import hashlib
import os

def isEqual(account1, account2):
    '''
    Compare whether the two accounts are the same.
    This function assumes that 'account1' and 'account2' are dictionaries
    containing account information, including a hashed password.
    It compares the usernames and the *hashed* passwords.  It does *not*
    compare plaintext passwords.

    Security Considerations:

    *   **Password Storage:**  This function assumes passwords are
        already hashed using a strong hashing algorithm (e.g., bcrypt,
        scrypt, or PBKDF2) and stored securely.  It *does not* perform
        the hashing itself.  The hashing should be done during account
        creation or password reset.
    *   **Salt:**  A unique salt should be used for each password hash.
        The salt should be stored alongside the hash.  This function
        assumes the salt is already incorporated into the stored hash.
    *   **Timing Attacks:**  This function is vulnerable to timing attacks
        if a simple string comparison is used for the hashed passwords.
        `hashlib.pbkdf2_hmac` with a secure salt and iteration count is recommended.
    *   **Configuration:**  Account details (usernames, hashed passwords)
        should be stored securely, ideally in a database with appropriate
        access controls.  Configuration files should be stored separately
        from the source code and have restricted access.
    *   **Principle of Least Privilege:** The user account running this
        code should have only the necessary privileges to access the
        account information.
    '''

    if not isinstance(account1, dict) or not isinstance(account2, dict):
        return False  # Or raise an exception:  raise TypeError("Accounts must be dictionaries")

    # Check if the necessary keys exist in the dictionaries.  This prevents
    # KeyError exceptions if the account data is incomplete.
    if 'username' not in account1 or 'username' not in account2 or \
       'hashed_password' not in account1 or 'hashed_password' not in account2:
        return False  # Or raise an exception: raise ValueError("Account dictionaries are missing required keys")

    # Compare usernames (case-insensitive)
    if account1['username'].lower() != account2['username'].lower():
        return False

    # Securely compare hashed passwords to prevent timing attacks.
    # Use a constant-time comparison function.  This example uses a simple
    # comparison, but a more robust solution is recommended, especially
    # if you are not using a library that already provides constant-time
    # comparison (e.g., bcrypt).

    # Constant-time comparison (more robust, but still not perfect)
    def compare_digest(a, b):
        """Constant-time comparison of two strings."""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        return result == 0

    # Compare the *hashed* passwords.  Crucially, we are *not* comparing
    # plaintext passwords.
    return compare_digest(account1['hashed_password'], account2['hashed_password'])


# Example Usage (Illustrative - Replace with secure storage and hashing)
if __name__ == '__main__':
    # In a real application, these would be retrieved from a secure database
    # or configuration file.  The passwords would be hashed using a strong
    # algorithm like bcrypt or PBKDF2 *before* being stored.

    # Example of hashing a password (DO NOT STORE PLAINTEXT PASSWORDS!)
    def hash_password(password, salt=None):
        """Hashes a password using PBKDF2-HMAC with a random salt."""
        if salt is None:
            salt = os.urandom(16)  # Generate a random salt
        
        # Use a strong hashing algorithm like PBKDF2-HMAC
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256',  # The hash digest algorithm for HMAC
            password.encode('utf-8'),  # Convert the password to bytes
            salt,  # Provide the salt
            100000  # It is recommended to use at least 100000 iterations of SHA256
        )
        return salt + hashed_password  # Store salt + hash

    # Example accounts (NEVER store passwords like this in real code!)
    password = "MySecurePassword123"
    hashed_password1 = hash_password(password)

    account_data1 = {
        'username': 'testuser',
        'hashed_password': hashed_password1
    }

    hashed_password2 = hash_password(password)
    account_data2 = {
        'username': 'testuser',
        'hashed_password': hashed_password2
    }

    account_data3 = {
        'username': 'anotheruser',
        'hashed_password': hash_password("DifferentPassword")
    }

    # Compare accounts
    print(f"Account 1 and Account 2 are equal: {isEqual(account_data1, account_data2)}")  # Should be True if same password and username
    print(f"Account 1 and Account 3 are equal: {isEqual(account_data1, account_data3)}")  # Should be False

