import re  # For regular expression email validation (Consider removing if email_validator is sufficient)
from email_validator import validate_email, EmailNotValidError
import bcrypt  # For password hashing

def validate_input(data):
    """Validates user input.  Returns a list of error messages."""
    errors = []
    username = data.get('username', '')
    password = data.get('password', '')
    first_name = data.get('first_name', '')
    last_name = data.get('last_name', '')
    email = data.get('email', '')

    if not all([username, password, first_name, last_name, email]):
        errors.append("All fields are required.")

    if not (4 <= len(username) <= 80):
        errors.append("Username must be between 4 and 80 characters.")

    if len(password) < 12:  # Increased minimum password length
        errors.append("Password must be at least 12 characters.")
    # TODO: Add password complexity checks (e.g., require uppercase, lowercase, numbers, symbols)
    # Example: if not re.search(r"[A-Z]", password): errors.append("Password must contain at least one uppercase letter.")


    if not (len(first_name) <= 80 and len(last_name) <= 80):
        errors.append("First and last names must be less than 80 characters.")

    try:
        # Use email_validator for robust email validation
        emailinfo = validate_email(email, check_deliverability=False) # set check_deliverability to True for production - this helps prevent registration with disposable or invalid email addresses, but can add latency.
        email = emailinfo.normalized
    except EmailNotValidError as e:
        errors.append(str(e))

    return errors


def hash_password(password):
    """Hashes the password using bcrypt."""
    # Adjust the rounds (cost factor) based on your server's capabilities.  Higher rounds increase security but also increase hashing time.
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    return hashed_password.decode('utf-8')  # Store as string

def verify_password(password, hashed_password):
    """Verifies the password against the stored hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False  # Handle potential bcrypt errors

# Example usage (Illustrative - adapt to your framework)
if __name__ == '__main__':
    user_data = {
        'username': 'testuser',
        'password': 'P@$$wOrd123!',
        'first_name': 'Test',
        'last_name': 'User',
        'email': 'test@example.com'
    }

    errors = validate_input(user_data)

    if errors:
        print("Validation Errors:")
        for error in errors:
            print(error)
    else:
        print("Input is valid.")
        hashed_password = hash_password(user_data['password'])
        print(f"Hashed password: {hashed_password}")

        # Store the username and hashed_password in the database (using parameterized queries!)
        # TODO: Implement database interaction using parameterized queries and handle potential database errors.
        # Example: try: cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password)) except Exception as e: print(f"Database error: {e}")

        # Example of password verification
        password_to_check = 'P@$$wOrd123!'
        if verify_password(password_to_check, hashed_password):
            print("Password verification successful!")
        else:
            print("Password verification failed.")

        # After successful login:
        # TODO: Set a secure cookie for session management.
        # Example: response.set_cookie('session_id', session_id, secure=True, httponly=True)

