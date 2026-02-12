import re
import sys
from secrets import randbelow
from typing import List, Optional


def get_id_from_sequence(id_sequence: List[int], index_str: str) -> Optional[int]:
    """
    Retrieves an ID from the id_sequence at the given index, after validating the index.

    Args:
        id_sequence: A list of IDs (integers).
        index_str: The index to access in the id_sequence, provided as a string.

    Returns:
        The ID at the specified index in the id_sequence, or None if the index is invalid.
        Prints an error message to stderr if the index is invalid.
    """

    # Validate the input index string using a regular expression.
    if not re.match(r"^\d+$", index_str):
        print("Error: Invalid input.", file=sys.stderr)  # More generic error message
        return None

    try:
        index = int(index_str)  # Convert the validated string to an integer.
    except ValueError:
        print("Error: Invalid input.", file=sys.stderr)  # More generic error message
        return None

    MAX_INDEX = 1000  # Example limit - adjust as needed
    if index > MAX_INDEX:
        print("Error: Invalid input.", file=sys.stderr)  # More generic error message
        return None

    # Validate the index is within the bounds of the id_sequence.
    if not (0 <= index < len(id_sequence)):
        print("Error: Invalid input.", file=sys.stderr)  # More generic error message
        return None

    try:
        # Access the element at the validated index.
        id_value = id_sequence[index]
        return id_value
    except IndexError:
        print("Error: Internal error.", file=sys.stderr)  # This should be unreachable due to the bounds check, but included for defensive programming.
        return None


if __name__ == "__main__":
    # Example usage with command-line arguments.
    if len(sys.argv) < 2:  # Correctly handle the case of no arguments
        print("Usage: python script.py <index>", file=sys.stderr)
        sys.exit(1)
    elif len(sys.argv) > 2:
        print("Usage: python script.py <index>", file=sys.stderr)
        sys.exit(1)

    index_str = sys.argv[1]

    # Example id_sequence (replace with your actual sequence).  Using random numbers for demonstration.
    id_sequence_length = 10
    id_sequence = [randbelow(100) for _ in range(id_sequence_length)]  # Generate a sequence of random numbers

    id_value = get_id_from_sequence(id_sequence, index_str)

    if id_value is not None:
        print(f"The ID at index {index_str} is: {id_value}")

