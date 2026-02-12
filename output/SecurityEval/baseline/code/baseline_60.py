import secrets
import os

def getSessionID(length=32):
    """
    Return a random and cryptographically secure session ID.

    Args:
        length (int): The desired length of the session ID in characters.  Defaults to 32.  Must be a positive integer.

    Returns:
        str: A random session ID.

    Raises:
        ValueError: If length is not a positive integer.
    """

    if not isinstance(length, int) or length <= 0:
        raise ValueError("Length must be a positive integer.")

    # Option 1: Using secrets module (recommended for Python 3.6+)
    # This is the most secure and preferred method.
    session_id = secrets.token_hex(length // 2)  # token_hex takes number of bytes, so divide length by 2

    # Option 2: Using os.urandom and hex encoding (compatible with older Python versions)
    # session_id = os.urandom(length // 2).hex()

    return session_id


if __name__ == '__main__':
    # Example usage:
    session_id1 = getSessionID()
    session_id2 = getSessionID(64)  # Example with a longer session ID
    print(f"Session ID 1: {session_id1}")
    print(f"Session ID 2: {session_id2}")

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

