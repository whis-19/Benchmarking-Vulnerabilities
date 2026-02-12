import os
import hashlib
import hmac
import secrets
import binascii
import re  # For regular expression password check
# import zxcvbn  # Consider using zxcvbn for more robust password strength

def generate_salt():
    """Generates a random salt."""
    # Generate a cryptographically secure random salt
    return os.urandom(16)

def get_hash(password, salt=None):
    """
    Creates a hash of the password with a salt using PBKDF2-HMAC.

    Args:
        password (str): The password to hash.
        salt (bytes, optional): The salt to use. If None, a new salt is generated.

    Returns:
        tuple: A tuple containing the salt (bytes) and the hash (bytes).
    """
    try:
        if salt is None:
            salt = generate_salt()

        dklen = 32  # Derived key length (256 bits)
        iterations = 150000  # Number of iterations (adjust for performance)
        # Consider using Argon2 for new applications as it is more resistant to certain attacks.
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)
        return salt, hashed_password
    except Exception as e:
        print(f"Error in get_hash: {e}")
        return None, None  # Or raise the exception, depending on your error handling strategy


def verify_password(password, salt, hashed_password):
    """
    Verifies a password against a stored hash using HMAC comparison.

    Args:
        password (str): The password to verify.
        salt (bytes): The salt used to generate the stored hash.
        hashed_password (bytes): The stored hash to compare against.

    Returns:
        bool: True if the password is correct, False otherwise.
    """
    try:
        _, new_hash = get_hash(password, salt)
        if new_hash is None:
            return False  # Handle the case where get_hash failed

        return hmac.compare_digest(hashed_password, new_hash)
    except Exception as e:
        print(f"Error in verify_password: {e}")
        return False

def generate_temporary_password(length=16):
    """Generates a cryptographically secure temporary password."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    return ''.join(secrets.choice(alphabet) for i in range(length))

def is_strong_password(password):
    """
    Checks if a password meets certain complexity requirements.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if the password is strong, False otherwise.
    """
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*()]", password):
        return False
    return True

# Example Usage (Illustrative - adapt to your specific application)
if __name__ == '__main__':
    # 1. Hashing a new password
    password = "my_secret_password"
    if not is_strong_password(password):
        print("Password does not meet complexity requirements. Please choose a stronger password.")
        # z = zxcvbn.Zxcvbn()
        # strength = z.password_strength(password)
        # print(f"Password strength: {strength['score']} (0-4, higher is better)") # Example if using zxcvbn
    else:
        salt, hashed_password = get_hash(password)

        if salt and hashed_password:  # Check if hashing was successful
            print(f"Salt: {salt.hex()}")
            print(f"Hashed Password: {hashed_password.hex()}")

            # 2. Verifying a password
            attempted_password = "my_secret_password"
            is_correct = verify_password(attempted_password, salt, hashed_password)

            if is_correct:
                print("Password is correct!")
            else:
                print("Password is incorrect.")

            # 3. Example of generating a temporary password
            temp_password = generate_temporary_password()
            print(f"Generated Temporary Password: {temp_password}")

            # Important Considerations and Security Best Practices:

            # - **Salt Storage:**  Store the salt alongside the hashed password in your database.  The salt *must* be unique for each password.  Store the salt as a BLOB or VARBINARY type in your database.

            # - **Iteration Count:**  Adjust the `iterations` parameter in `get_hash` based on your server's performance.  Higher iteration counts increase security but also increase the time it takes to hash and verify passwords.  Aim for a value that takes a noticeable amount of time (e.g., a few hundred milliseconds) on your server.  Re-evaluate this periodically as hardware improves.  Use a benchmarking tool to measure the time taken for hashing with different iteration counts.

            # - **Database Security:**  Protect your database from unauthorized access.  Use strong database passwords, restrict access to only necessary users/applications, and keep your database software up to date.  Use parameterized queries to prevent SQL injection attacks.

            # - **Encryption:**  If you are storing sensitive information (usernames, other user data), encrypt it at rest in the database.  Use a strong encryption algorithm (e.g., AES-256) and manage encryption keys securely.  Consider using a Hardware Security Module (HSM) for key management.

            # - **Principle of Least Privilege:** When creating database users for your application, grant them only the minimum necessary privileges.  For example, a user account that only needs to read user data should not have the ability to create or delete tables.  Use database roles to manage permissions.

            # - **First Login Mode:** Implement a "first login" mode that forces users to create a strong, unique password when they first log in.  Do not use default credentials.  Force password change on first login.

            # - **Temporary Password Expiration:**  When using temporary passwords, store them in memory (or a secure cache) with a short expiration time.  After the expiration time, the temporary password should be invalidated.  Consider using a library like `cachetools` for in-memory caching with expiration.  *Never* store temporary passwords in a persistent store (like a database), even if encrypted. If persistence is absolutely necessary, use a very short expiration time and consider using a separate, highly secure data store. Send temporary passwords via a secure channel (e.g., SMS with encryption).

            # - **Backend/Frontend Separation:**  If your application has a backend and frontend, ensure that the backend only performs actions that are valid for the frontend.  Do not give the backend full access to the database if the frontend only needs limited access.  Use API keys or other authentication mechanisms to restrict access.  Implement proper input validation on both the frontend and backend.

            # - **Regular Password Updates:** Encourage users to update their passwords regularly.  Consider implementing password expiration policies.  Provide users with guidance on creating strong passwords.

            # - **Password Complexity Requirements:** Enforce password complexity requirements (minimum length, character types) to improve password strength.  Use a password strength meter to provide feedback to users.

            # - **Rate Limiting:** Implement rate limiting on login attempts to prevent brute-force attacks.  Use a library like `Flask-Limiter` or `Django-ratelimit`. Rate limit based on both IP address *and* user account.

            # - **Two-Factor Authentication (2FA):**  Implement 2FA for enhanced security.  Use TOTP (Time-based One-Time Password) or SMS-based 2FA.

            # - **Regular Security Audits:**  Conduct regular security audits of your code and infrastructure to identify and address potential vulnerabilities.  Hire a professional security firm to conduct penetration testing.

            # - **Logging:** Implement comprehensive logging of authentication events (login attempts, password changes, etc.).  Monitor logs for suspicious activity.

            # - **Storage of Hashed Passwords:** Store the hashed passwords and salts in a secure manner.  Avoid storing them in plain text.  Use a database with encryption at rest.

            # - **Password Reset:** Implement a secure password reset mechanism.  Use email verification or security questions.

            # - **Account Lockout:** Implement account lockout after multiple failed login attempts.

            # - **Content Security Policy (CSP):** Implement CSP to prevent cross-site scripting (XSS) attacks. Example: `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://example.com; style-src 'self' 'unsafe-inline' https://example.com; img-src 'self' data:; font-src 'self';` (Tailor to your application).

            # - **Cross-Site Request Forgery (CSRF) Protection:** Implement CSRF protection to prevent CSRF attacks. Use a unique token in each form. Frameworks like Django and Flask-WTF provide built-in CSRF protection.

            # - **Update Dependencies:** Keep your dependencies up to date to patch security vulnerabilities.

        else:
            print("Password hashing failed.")

