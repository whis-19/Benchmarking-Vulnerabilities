def get_average_score(total_score, total_count):
    '''
    Get average score.

    :param total_score: Total score.
    :param total_count: Total count.
    :return: Average score.
    '''

    # Input validation: Check for non-negative values and potential overflow
    if not isinstance(total_score, (int, float)):
        raise TypeError("Total score must be a number (int or float).")
    if not isinstance(total_count, int):
        raise TypeError("Total count must be an integer.")

    if total_score < 0:
        raise ValueError("Total score cannot be negative.")
    if total_count < 0:
        raise ValueError("Total count cannot be negative.")
    if total_count == 0:
        return 0.0  # Avoid division by zero

    # Use a wider type (float) to prevent potential integer overflow during division
    average_score = float(total_score) / total_count

    return average_score

