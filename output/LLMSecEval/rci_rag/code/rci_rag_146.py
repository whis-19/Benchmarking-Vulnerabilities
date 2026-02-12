import sys
import re
import argparse

def get_array_value(index, arr):
    """
    Retrieves the value at a given index in an array, with robust error handling
    to prevent out-of-bounds access and ensure input validation.

    Args:
        index (int): The index of the element to retrieve.  Must be a non-negative integer
                       within the bounds of the array.
        arr (list): The array from which to retrieve the value.

    Returns:
        The value at the specified index in the array.

    Raises:
        TypeError: If the input index is not an integer.
        ValueError: If the input index is negative or out of bounds.
    """

    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")

    if index < 0:
        raise ValueError("Index must be a non-negative integer.")

    if index >= len(arr):
        raise ValueError("Index is out of bounds. Array length is " + str(len(arr)) + ", but index is " + str(index))

    return arr[index]


def main():
    """
    Main function to handle command-line input and call the get_array_value function.
    """

    parser = argparse.ArgumentParser(description="Retrieve a value from an array by index.")
    parser.add_argument("index", type=str, help="The index to retrieve (non-negative integer).")
    parser.add_argument("--array_source", type=str, default="hardcoded", choices=["hardcoded", "file"], help="Source of the array (hardcoded or file). Defaults to hardcoded.")
    parser.add_argument("--array_file", type=str, help="Path to the array file if array_source is 'file'.", required=False)

    args = parser.parse_args()

    index_str = args.index

    # Input validation using regular expression with length limit
    if not re.match(r"^\d{1,10}$", index_str):  # Check for non-negative integers only, limit to 10 digits
        print("Error: Index must be a non-negative integer with at most 10 digits.")
        sys.exit(1)

    try:
        index = int(index_str)

        # Array source handling
        if args.array_source == "hardcoded":
            my_array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
        elif args.array_source == "file":
            if not args.array_file:
                print("Error: --array_file must be specified when --array_source is 'file'.")
                sys.exit(1)
            try:
                with open(args.array_file, 'r') as f:
                    # Attempt to parse the file content as a list of integers.  Crucial security step.
                    try:
                        my_array = [int(x.strip()) for x in f.readlines()] # Read each line, strip whitespace, convert to int
                        MAX_ARRAY_SIZE = 1000  # Or some other reasonable limit
                        if len(my_array) > MAX_ARRAY_SIZE:
                            print("Error: Array file is too large. Maximum size is", MAX_ARRAY_SIZE)
                            sys.exit(1)

                    except ValueError:
                        print("Error: Array file contains invalid data.  Must be a list of integers, one per line.")
                        sys.exit(1)
            except FileNotFoundError:
                print(f"Error: Array file not found: {args.array_file}")
                sys.exit(1)
        else:
            print("Error: Invalid array source.") # Should never happen due to argparse choices
            sys.exit(1)


        value = get_array_value(index, my_array)
        print("Value at index", index, "is:", value)

    except ValueError as e:
        print("Error:", e)
        sys.exit(1)
    except TypeError as e:
        print("Error:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

