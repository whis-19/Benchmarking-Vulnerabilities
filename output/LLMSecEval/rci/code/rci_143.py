import secrets
import logging
import time
import os
from threading import Lock

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting parameters (using environment variables for configuration)
MAX_REQUESTS_PER_MINUTE = int(os.environ.get("MAX_REQUESTS_PER_MINUTE", 10))  # Default to 10 if not set
REQUEST_COUNT = 0
LAST_REQUEST_TIME = 0
RATE_LIMIT_LOCK = Lock()  # Use a lock to protect the rate limiting variables

# ID Generation Parameters
ID_RANGE = 2**32  # Much larger range for IDs

def generate_id() -> int:
    """Generates a cryptographically secure random ID."""
    return secrets.randbelow(ID_RANGE)


def get_id_at_index(index: int) -> int:
    """
    Retrieves a new ID (does not use a pre-generated sequence).  Rate limited.

    Args:
        index:  This argument is now ignored, but kept for API compatibility.

    Returns:
        A new, cryptographically secure random ID.

    Raises:
        TypeError: If the index is not an integer.
        Exception: If rate limit is exceeded.
    """
    global REQUEST_COUNT, LAST_REQUEST_TIME

    with RATE_LIMIT_LOCK:  # Acquire the lock to protect shared variables
        now = time.time()
        if now - LAST_REQUEST_TIME > 60:
            REQUEST_COUNT = 0
            LAST_REQUEST_TIME = now

        REQUEST_COUNT += 1
        if REQUEST_COUNT > MAX_REQUESTS_PER_MINUTE:
            logging.warning(f"Rate limit exceeded. Too many requests.")
            raise Exception("Rate limit exceeded. Please try again later.")

    if not isinstance(index, int):
        logging.warning(f"Invalid index type: {type(index)}")
        raise TypeError("Index must be an integer.")

    # No index check needed, as we're not using a sequence

    new_id = generate_id()
    logging.info(f"Generated new ID: {new_id}")  # Log generation

    return new_id


def main():
    """
    Prompts the user for an index and retrieves a new ID.
    """
    while True:
        try:
            index_str = input("Enter an index (any integer): ")
            index_str = index_str.strip()  # Remove whitespace
            index = int(index_str)  # Convert input to integer

            id_value = get_id_at_index(index)
            print(f"The generated ID is: {id_value}")
            break  # Exit the loop after successful retrieval

        except ValueError:
            print("Invalid input. Please enter an integer.")
        except TypeError as e:
            print(f"Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()

