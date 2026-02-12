import re
import sys
import secrets
import logging
import argparse
import os  # For environment variables
import uuid  # For generating unique IDs

# Configure logging to avoid printing sensitive information to the console in production
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a maximum index (example - adjust based on your actual data)
# Read from environment variable, default to 9 if not set
MAX_INDEX = int(os.environ.get("MAX_INDEX", "9"))
# MAX_INDEX = 9  # Example:  If the ID sequence represents database keys, this might be the maximum key value.
# Explanation: MAX_INDEX limits access to a subset of IDs for authorization purposes.

def get_id_from_sequence(id_sequence, index_str):
    """
    Retrieves an ID from the id_sequence at the given index, after validating the index.

    Args:
        id_sequence: A list of IDs (integers).
        index_str: The index to retrieve, provided as a string.

    Returns:
        The ID at the specified index, or None if the index is invalid.
    """

    try:
        # 1. Input Validation: Validate the user input using a regular expression.
        if not re.match(r"^\d+$", index_str):  # Check if the input is a non-negative integer
            logging.error("Invalid index format.  Please provide a non-negative integer.")
            return None

        # Sanitize the input by removing leading zeros
        index_str = index_str.lstrip('0')
        if not index_str:  # Handle the case where the string was all zeros
            index = 0
        else:
            index = int(index_str)

        # 2. Input Validation: Check for out-of-bounds access.
        if not 0 <= index < len(id_sequence):
            logging.error(f"Index {index} is out of bounds.  Valid range is 0 to {len(id_sequence) - 1}.")
            return None

        # 3. Whitelist Validation (Optional):  Further restrict the index if appropriate.
        if index > MAX_INDEX:
            logging.error(f"Index {index} exceeds the maximum allowed index of {MAX_INDEX}.")
            return None

        # 5, 6, 7. Integer Operations & Out-of-Bounds:  The check above prevents out-of-bounds access.
        # Using standard Python list indexing, which raises IndexError if out of bounds (handled above).
        # No need for unsigned integers here as the index is validated to be within bounds.

        id_value = id_sequence[index]
        return id_value

    except ValueError as e:
        # Handle potential errors during integer conversion.
        logging.error(f"Error converting index to integer: {e}")
        return None
    except IndexError as e:  # More specific exception
        logging.error(f"IndexError: {e}") # Log the specific error
        return None
    except Exception as e:
        # Catch any other unexpected errors.  Avoid revealing sensitive details in the error message.
        logging.exception("An unexpected error occurred during index retrieval.") # Log the full exception
        return None


def main():
    """
    Main function to handle user input and retrieve the ID.
    """

    # Example ID sequence (replace with your actual data).  Use a secure method to generate this in a real application.
    # These IDs might represent database keys, session identifiers, or other unique identifiers.
    # The security considerations depend on what these IDs represent.
    # 10. Secure Random Number Generation (Example - replace with your actual ID generation)
    # id_sequence = [secrets.randbelow(1000) for _ in range(10)] # Generate 10 random IDs between 0 and 999

    # Generate a sequence of UUIDs for more secure and unique IDs
    id_sequence = [str(uuid.uuid4()) for _ in range(10)]

    # 4. Command Line Arguments: Get the index from the command line.
    parser = argparse.ArgumentParser(description="Retrieve an ID from a sequence by index.")  # Use argparse
    parser.add_argument("index", type=str, help="The index of the ID to retrieve.")
    args = parser.parse_args()

    index_str = args.index

    # Get the ID from the sequence.
    id_value = get_id_from_sequence(id_sequence, index_str)

    if id_value is not None:
        # 8, 9. Output Encoding:  Ensure proper output encoding (UTF-8 is generally a good default).
        # No escaping or quoting needed here as we're just printing an integer.
        print(f"ID at index {index_str}: {id_value}")


if __name__ == "__main__":
    main()

