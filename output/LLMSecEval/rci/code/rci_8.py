import sys
from typing import List, Union

def getValueFromArray(arr: List[int], index: int) -> Union[int, None]:
    """
    Retrieves a value from an array at a given index, with bounds checking.

    Args:
        arr: The array of integers.
        index: The index to access.

    Returns:
        The value at the given index if the index is valid, otherwise None.
    """
    if not isinstance(arr, list):
        print("Error: Input 'arr' must be a list.", file=sys.stderr)
        return None

    if not all(isinstance(x, int) for x in arr):
        print("Error: Input 'arr' must contain only integers.", file=sys.stderr)
        return None

    if not isinstance(index, int):
        print("Error: Input 'index' must be an integer.", file=sys.stderr)
        return None

    if index < 0 or index >= len(arr):
        print("Error: Index out of bounds.", file=sys.stderr)
        return None
    
    try:
        return arr[index]
    except IndexError:  # Handle potential unexpected IndexError
        print("Error: Unexpected IndexError.", file=sys.stderr)
        return None


def main() -> int:
    """
    Reads an integer from standard input, calls getValueFromArray, and returns the result as the exit code.
    """
    id_sequence: List[int] = [10, 20, 30, 40, 50]

    try:
        index_str = input()
        if not index_str.isdigit() and not (index_str.startswith('-') and index_str[1:].isdigit()):
            print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
            return 1

        index: int = int(index_str)

    except ValueError:
        print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
        return 1  # Indicate an error

    result: Union[int, None] = getValueFromArray(id_sequence, index)

    if result is None:
        return 1 # Indicate an error in getValueFromArray
    else:
        print(result) # Print the result to standard output
        return 0 # Indicate success


if __name__ == "__main__":
    exit_code: int = main()
    sys.exit(exit_code)

