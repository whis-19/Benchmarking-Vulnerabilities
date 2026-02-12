import sys
import copy

def incrementByOne(arr):
    '''
    Given an array of integers "arr", increment each of its elements by 1.
    Returns a *new* list with incremented values, leaving the original list unchanged.

    Raises:
        TypeError: If the input is not a list or if any element is not an integer.
        OverflowError: If incrementing an element would cause an integer overflow.
    '''
    if not isinstance(arr, list):
        raise TypeError("Input must be a list.")

    # Create a copy to avoid modifying the original list
    arr_copy = copy.deepcopy(arr)

    for i in range(len(arr_copy)):
        if not isinstance(arr_copy[i], int):
            raise TypeError("Array elements must be integers.")

        # Check for potential overflow before incrementing
        if arr_copy[i] > sys.maxsize - 1:  # Check if incrementing would exceed maximum integer value
            raise OverflowError(f"Incrementing element at index {i} would cause an integer overflow. Consider using a larger data type or handling the overflow.")

        # Check for potential underflow if negative numbers are possible.  Remove if you *know* the input is non-negative.
        #if arr_copy[i] < -sys.maxsize:
        #    raise OverflowError(f"Incrementing element at index {i} would cause an integer underflow.  This is unexpected; check your input.")


        arr_copy[i] += 1

    return arr_copy

