import secrets
import os
import hashlib  # For secure storage
import datetime  # For session expiration

# In a real application, you'd use a database or other secure storage mechanism.
# This is just a placeholder.
session_store = {}


def getSessionID(length=32):
    """
    Return a random and cryptographically secure session ID.

    Args:
        length (int): The desired length of the session ID in characters.  Defaults to 32.  Must be a positive integer.
                       Consider an upper limit to prevent resource exhaustion.

    Returns:
        str: A random session ID.

    Raises:
        ValueError: If length is not a positive integer.

    Security Considerations:
    - Session IDs should be stored securely (e.g., hashed and salted in a database).
    - Session IDs should be transmitted over HTTPS to prevent eavesdropping.
    - Session IDs should have a reasonable expiration time to limit the window of opportunity for attackers.
    - Consider regenerating the session ID after a successful login or after a period of inactivity.
    - If using cookies, set the HttpOnly and Secure flags to mitigate XSS and ensure transmission only over HTTPS.
    """

    if not isinstance(length, int) or length <= 0:
        raise ValueError("Length must be a positive integer.")

    if length > 128:  # Example upper limit
        raise ValueError("Length exceeds maximum allowed value.")

    session_id = secrets.token_hex(length // 2)

    return session_id


def create_session(user_id):
    """Creates a session for a given user."""
    session_id = getSessionID()
    # Securely store the session ID (e.g., hash and salt it)
    hashed_session_id = hashlib.sha256(session_id.encode('utf-8')).hexdigest()  # Example hashing
    salt = os.urandom(16).hex()  # Generate a random salt
    salted_hashed_session_id = hashlib.sha256((salt + hashed_session_id).encode('utf-8')).hexdigest()

    # Store the salted hash in the session store along with user ID and expiration time
    session_store[salted_hashed_session_id] = {
        'user_id': user_id,
        'expiration': datetime.datetime.now() + datetime.timedelta(hours=1),  # Example: 1-hour expiration
        'salt': salt
    }
    return session_id  # Return the *unhashed* session ID to the client (e.g., in a cookie)


def validate_session(session_id):
    """Validates a session ID and returns the associated user ID if valid, None otherwise."""
    hashed_session_id = hashlib.sha256(session_id.encode('utf-8')).hexdigest()
    for salted_hashed_session_id, session_data in session_store.items():
        salt = session_data['salt']
        if hashlib.sha256((salt + hashed_session_id).encode('utf-8')).hexdigest() == salted_hashed_session_id:
            if session_data['expiration'] > datetime.datetime.now():
                return session_data['user_id']  # Session is valid
            else:
                # Session expired, remove it
                del session_store[salted_hashed_session_id]
                return None
    return None  # Session not found


if __name__ == '__main__':
    # Example usage:
    user_id = 123
    session_id = create_session(user_id)
    print(f"Session ID created: {session_id}")

    # Simulate a request with the session ID
    validated_user_id = validate_session(session_id)
    if validated_user_id:
        print(f"Session is valid for user: {validated_user_id}")
    else:
        print("Session is invalid.")

    # Simulate an invalid session ID
    invalid_session_id = "invalid_session_id"
    validated_user_id = validate_session(invalid_session_id)
    if validated_user_id:
        print(f"Session is valid for user: {validated_user_id}")
    else:
        print("Session is invalid.")

    # Demonstrating uniqueness (high probability)
    session_ids = set()
    for _ in range(1000):
        session_id = getSessionID()
        if session_id in session_ids:
            print("Collision detected!")
            break
        session_ids.add(session_id)
    else:
        print("No collisions detected after generating 1000 session IDs.")

    # Example of handling invalid length
    try:
        session_id_invalid = getSessionID(0)
    except ValueError as e:
        print(f"Error: {e}")

    try:
        session_id_invalid = getSessionID(-10)
    except ValueError as e:
        print(f"Error: {e}")

    try:
        session_id_invalid = getSessionID("abc")
    except ValueError as e:
        print(f"Error: {e}")

