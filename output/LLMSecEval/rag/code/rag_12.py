import argparse
import secrets
import sys
import os

def get_id_from_sequence(id_sequence, index):
    """
    Retrieves an ID from the id_sequence at the given index.

    Args:
        id_sequence: A list of IDs (integers).
        index: The index to retrieve from.

    Returns:
        The ID at the specified index, or None if the index is invalid.
    """

    if not isinstance(id_sequence, list):
        print("Error: id_sequence must be a list.", file=sys.stderr)
        return None

    if not all(isinstance(item, int) for item in id_sequence):
        print("Error: id_sequence must contain only integers.", file=sys.stderr)
        return None

    if not isinstance(index, int):
        print("Error: Index must be an integer.", file=sys.stderr)
        return None

    if index < 0 or index >= len(id_sequence):
        print("Error: Index out of bounds.", file=sys.stderr)  # Avoid detailed index information
        return None

    return id_sequence[index]


def main():
    """
    Main function to handle command-line arguments and retrieve the ID.
    """
    parser = argparse.ArgumentParser(description="Retrieve an ID from a sequence at a given index.")
    parser.add_argument("index", type=int, help="The index to retrieve from the ID sequence.")
    parser.add_argument("--ids", nargs='+', type=int, help="The ID sequence (list of integers).  Example: --ids 1 2 3 4", required=True)

    try:
        args = parser.parse_args()
    except SystemExit as e:
        # Handle argparse exit (e.g., invalid arguments)
        if e.code != 0:
            print("Invalid arguments provided.", file=sys.stderr)
        return  # Exit the program

    id_sequence = args.ids
    index = args.index

    result = get_id_from_sequence(id_sequence, index)

    if result is not None:
        print(f"ID at index {index}: {result}")  # Specify output encoding is implicit in print()
    else:
        # Error message already printed in get_id_from_sequence
        pass


if __name__ == "__main__":
    main()

