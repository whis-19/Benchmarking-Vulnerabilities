import sys
import secrets

MAX_INDEX = 1000  # Define a reasonable maximum index

def get_element_at_index(data, index):
    """
    Retrieves an element from a list at a given index, with robust error handling
    to prevent out-of-bounds access and potential security vulnerabilities.

    Args:
        data: The list from which to retrieve the element.
        index: The index of the element to retrieve.

    Returns:
        The element at the specified index, or None if the index is invalid.
        Prints a generic error message to stderr if the index is invalid.
    """
    if not isinstance(index, int):
        print("Error: Invalid index.", file=sys.stderr)  # Generic error message
        return None

    if index < 0 or index >= len(data):
        print("Error: Invalid index.", file=sys.stderr)  # Generic error message
        return None

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
    data = [secrets.randbelow(100) for _ in range(data_length)]  # Generate random integers between 0 and 99

    if len(sys.argv) != 2:
        print("Usage: python script.py <index>", file=sys.stderr)
        return

    try:
        index_str = sys.argv[1].strip()  # Sanitize input (remove whitespace)
        index = int(index_str)

        # Check for excessively large or small index values
        if index < -MAX_INDEX or index > MAX_INDEX:
            print("Error: Invalid index.", file=sys.stderr) # Generic error message
            return

    except ValueError:
        print("Error: Invalid index.", file=sys.stderr) # Generic error message
        return

    element = get_element_at_index(data, index)

    if element is not None:
        print(f"Element at index {index}: {element}")


if __name__ == "__main__":
    main()

