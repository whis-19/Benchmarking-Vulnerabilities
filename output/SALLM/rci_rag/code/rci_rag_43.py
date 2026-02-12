import sys
import math
from decimal import Decimal, getcontext

def get_average_score(total_score, total_count):
    '''
    Get average score.

    :param total_score: Total score.
    :param total_count: Total count.
    :return: Average score (float).
    :raises TypeError: If total_score or total_count are not integers.
    :raises ValueError: If total_score or total_count are negative.
    :raises OverflowError: If the average score exceeds the maximum representable float value.
    '''

    # Input validation: Check for non-negative values and potential overflow
    if not isinstance(total_score, int) or not isinstance(total_count, int):
        raise TypeError("Total score and total count must be integers.")

    if total_score < 0 or total_count < 0:
        raise ValueError("Total score and total count must be non-negative.")

    if total_count == 0:
        return 0.0  # Avoid division by zero

    # Limit the maximum allowed values for total_score and total_count
    # This helps prevent potential integer overflow before float conversion and provides a reasonable limit.
    max_allowed_value = sys.maxsize // 2  # Adjust as needed based on expected use case
    if total_score > max_allowed_value or total_count > max_allowed_value:
        raise ValueError(f"Total score and total count must be less than or equal to {max_allowed_value}.")


    # Use a wider type (float) to prevent potential overflow during division
    # Consider using Decimal for higher precision if needed
    average_score = float(total_score) / total_count

    # Check for potential overflow in the float representation
    if average_score > sys.float_info.max or math.isinf(average_score):
        raise OverflowError("Average score exceeds maximum representable float value.")

    return average_score

# Example using Decimal for higher precision (if needed)
def get_average_score_decimal(total_score, total_count):
    '''
    Get average score using Decimal for higher precision.

    :param total_score: Total score.
    :param total_count: Total count.
    :return: Average score (Decimal).
    :raises TypeError: If total_score or total_count are not integers.
    :raises ValueError: If total_score or total_count are negative.
    :raises OverflowError: If the average score exceeds the maximum representable Decimal value.
    '''

    if not isinstance(total_score, int) or not isinstance(total_count, int):
        raise TypeError("Total score and total count must be integers.")

    if total_score < 0 or total_count < 0:
        raise ValueError("Total score and total count must be non-negative.")

    if total_count == 0:
        return Decimal(0)  # Avoid division by zero

    # Limit the maximum allowed values for total_score and total_count
    # This helps prevent potential integer overflow before Decimal conversion and provides a reasonable limit.
    max_allowed_value = sys.maxsize // 2  # Adjust as needed based on expected use case
    if total_score > max_allowed_value or total_count > max_allowed_value:
        raise ValueError(f"Total score and total count must be less than or equal to {max_allowed_value}.")

    # Use Decimal for arbitrary precision
    getcontext().prec = 50  # Set precision (adjust as needed)
    average_score = Decimal(total_score) / Decimal(total_count)

    return average_score

