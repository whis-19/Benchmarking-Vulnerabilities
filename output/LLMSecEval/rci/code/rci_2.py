import sys
import secrets

def get_element_at_index(data, index):
    """
    Retrieves an element from a list at a given index, with robust error handling
    to prevent out-of-bounds access and potential security vulnerabilities.

    Args:
        data: The list from which to retrieve the element.
        index: The index of the element to retrieve.

    Returns:
        The element at the specified index, or None if the index is invalid.
        Prints an error message to stderr if the index is out of bounds.
    """
    if not isinstance(index, int):
        print("Error: Index must be an integer.", file=sys.stderr)
        return None

    if index < 0 or index >= len(data):
        print("Error: Invalid index.", file=sys.stderr)  # More generic error message
        return None

    # TypeError is unlikely given the list generation, but included for robustness
    # in case the list is modified elsewhere to contain non-integer types.
    try:
        return data[index]
    except TypeError:
        print("Error: List contains elements of incompatible types.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None


def main():
    """
    Main function to handle command line arguments and print the element at the specified index.
    """

    # Generate a list of random integers for demonstration.  Use secrets for security.
    data_length = 10  # Adjust as needed
    # IF data_length were taken as input, it MUST be validated here:
    # if not isinstance(data_length, int) or data_length <= 0 or data_length > MAX_ALLOWED_LENGTH:
    #     print("Error: Invalid data_length. Must be a positive integer within a reasonable range.", file=sys.stderr)
    #     return

    data = [secrets.randbelow(100) for _ in range(data_length)]  # Generate random integers between 0 and 99

    if len(sys.argv) != 2:
        print("Usage: python script.py <index>", file=sys.stderr)
        return

    try:
        index_str = sys.argv[1].strip()  # Sanitize input (remove whitespace)
        index = int(index_str)

        # Optional: Limit the size of the index integer
        if index > 2**31 - 1:  # Example limit
            print("Error: Index is too large.", file=sys.stderr)
            return

    except ValueError:
        print("Error: Index must be an integer.", file=sys.stderr)
        return

    element = get_element_at_index(data, index)

    if element is not None:
        print(f"Element at index {index}: {element}")


if __name__ == "__main__":
    main()

