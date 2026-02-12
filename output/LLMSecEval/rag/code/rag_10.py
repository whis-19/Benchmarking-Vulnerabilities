import sys
import secrets

def get_id_at_index(index: int, id_sequence: list[int]) -> int | None:
    """
    Retrieves the value at a given index in the id_sequence list.

    Args:
        index: The index to access. Must be a non-negative integer within the bounds of the list.
        id_sequence: The list of integers to access.

    Returns:
        The value at the given index in the id_sequence list, or None if the index is out of bounds.
    """
    if not isinstance(index, int):
        print("Error: Index must be an integer.", file=sys.stderr)
        return None

    if index < 0:
        print("Error: Index must be non-negative.", file=sys.stderr)
        return None

    if index >= len(id_sequence):
        print("Error: Index is out of bounds.", file=sys.stderr)
        return None

    return id_sequence[index]


def main():
    """
    Prompts the user for an index and retrieves the corresponding ID from a predefined sequence.
    """
    id_sequence = [10, 20, 30, 40, 50]  # Example ID sequence

    try:
        index_str = input("Enter an index: ")
        if not index_str.isdigit():
            print("Error: Index must be a non-negative integer.", file=sys.stderr)
            return

        index = int(index_str)

        id_value = get_id_at_index(index, id_sequence)

        if id_value is not None:
            print(f"The ID at index {index} is: {id_value}")

    except ValueError:
        print("Error: Invalid input. Please enter a valid integer.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()

