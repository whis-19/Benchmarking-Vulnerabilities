import secrets

# Generate a cryptographically secure random sequence of IDs.
# The length of the sequence can be adjusted as needed.
ID_SEQUENCE_LENGTH = 100  # Example length
id_sequence = [secrets.randbelow(1000000) for _ in range(ID_SEQUENCE_LENGTH)]  # Example range of IDs


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
        raise IndexError(f"Index {index} is out of bounds. Valid range is 0 to {len(id_sequence) - 1}.")

    return id_sequence[index]


def main():
    """
    Prompts the user for an index and retrieves the corresponding ID.
    Handles potential errors gracefully.
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
        except IndexError as e:
            print(e)  # Print the specific IndexError message
        except TypeError as e:
            print(e) # Print the specific TypeError message
        except KeyboardInterrupt:
            print("\nExiting...")
            break


if __name__ == "__main__":
    main()

