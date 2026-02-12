import secrets
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a cryptographically secure random sequence of IDs.
ID_SEQUENCE_LENGTH = 100
ID_RANGE = 1000000
id_sequence = [secrets.randbelow(ID_RANGE) for _ in range(ID_SEQUENCE_LENGTH)]


def get_id_at_index(index: int) -> int:
    """
    Retrieves the ID at the specified index in the id_sequence array.

    Args:
        index: The index of the ID to retrieve.

    Returns:
        The ID at the specified index.

    Raises:
        TypeError: If the index is not an integer.
        IndexError: If the index is out of bounds.
    """

    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")

    if not 0 <= index < len(id_sequence):
        logging.warning(f"Attempted access with out-of-bounds index: {index}")
        raise IndexError("Invalid index.")

    return id_sequence[index]


def main():
    """
    Prompts the user for an index and retrieves the corresponding ID.
    Handles potential errors gracefully.
    """
    while True:
        try:
            index_str = input(f"Enter an index (0 to {ID_SEQUENCE_LENGTH - 1}): ")
            try:
                index = int(index_str)
            except ValueError:
                print("Invalid input.")  # More generic error message
                continue

            if not 0 <= index < ID_SEQUENCE_LENGTH:  # Explicit range check
                print("Invalid index.")
                continue

            id_value = get_id_at_index(index)
            print(f"The ID at index {index} is: {id_value}")
            break

        except IndexError:
            print("Invalid index.")
        except TypeError as e:
            print(e)
        except KeyboardInterrupt:
            print("\nExiting...")
            break


if __name__ == "__main__":
    main()

