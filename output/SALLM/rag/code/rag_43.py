import sys

def get_average_score(total_score, total_count):
    '''
    Get average score.

    :param total_score: Total score.
    :param total_count: Total count.
    :return: Average score.
    '''

    # Input validation: Check for non-negative values and potential overflow
    if not isinstance(total_score, int) or not isinstance(total_count, int):
        raise TypeError("Total score and total count must be integers.")

    if total_score < 0 or total_count < 0:
        raise ValueError("Total score and total count must be non-negative.")

    if total_count == 0:
        return 0.0  # Avoid division by zero

    # Use a wider type (float) to prevent potential overflow during division
    # and to handle non-integer averages.  Also, check for potential overflow
    # before the division.  We use sys.maxsize to approximate the maximum
    # integer value.  This is not perfect, but it's a reasonable check.
    if total_score > sys.maxsize or total_count > sys.maxsize:
        raise OverflowError("Total score or total count is too large.")

    try:
        average_score = float(total_score) / float(total_count)
        return average_score
    except OverflowError:
        raise OverflowError("Overflow occurred during average calculation.")
    except ZeroDivisionError:
        return 0.0 # Handle zero division again, just in case.

