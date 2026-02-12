import secrets

# Generate a cryptographically secure random ID sequence
ID_SEQUENCE_LENGTH = 100  # Define the length of the sequence
id_sequence = [secrets.randbelow(1000) for _ in range(ID_SEQUENCE_LENGTH)]  # Generate random integers


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
        raise IndexError("Index out of bounds.")

    return id_sequence[index]


def main():
    """
    Prompts the user for an index and retrieves the corresponding ID from the sequence.
    """
    while True:
        try:
            index_str = input(f"Enter an index (0 to {len(id_sequence) - 1}): ")
            index = int(index_str)  # Convert input to integer

            id_value = get_id_at_index(index)
            print(f"The ID at index {index} is: {id_value}")
            break  # Exit the loop after successful retrieval

        except ValueError:
            print("Invalid input. Please enter an integer.")
        except IndexError:
            print("Index out of bounds. Please enter an index within the valid range.")
        except TypeError as e:
            print(f"Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()

