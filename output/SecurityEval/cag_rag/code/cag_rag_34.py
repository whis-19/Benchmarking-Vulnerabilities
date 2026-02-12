def incrementByOne(arr):
    '''
    Given an array of integers "arr", increment each of its elements by 1
    '''
    if not isinstance(arr, list):
        raise TypeError("Input must be a list.")

    for i in range(len(arr)):
        if not isinstance(arr[i], int):
            raise TypeError("Elements of the list must be integers.")

        # Check for potential overflow before incrementing.  Using a wider type (long)
        # to perform the addition and then checking if it's within the valid range
        # for a standard Python integer.  This mitigates overflow issues.
        temp_val = int(arr[i]) + 1  # Convert to int to handle potential non-integer input that can be cast to int

        if temp_val > (2**63 - 1):  # Maximum value for a signed 64-bit integer (Python's int)
            raise OverflowError("Incrementing element at index {} would cause an integer overflow.".format(i))
        elif temp_val < -(2**63): # Minimum value for a signed 64-bit integer
            raise OverflowError("Incrementing element at index {} would cause an integer underflow.".format(i))

        arr[i] = int(temp_val)  # Convert back to int after checking for overflow

    return arr

