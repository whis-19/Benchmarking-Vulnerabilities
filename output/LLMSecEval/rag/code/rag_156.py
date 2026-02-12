import sys

def getMonthlySales(month: int) -> int:
    """
    Retrieves monthly sales data.  This is a placeholder function.
    In a real application, this would likely access a database or other data source.

    Args:
        month: The month (0-indexed, so 0 is January, 1 is February, etc.).

    Returns:
        The sales for the given month.  Returns 0 if the month is invalid.
    """
    if not (0 <= month <= 11):  # Validate month input
        print(f"Error: Invalid month: {month}. Month must be between 0 and 11.", file=sys.stderr)
        return 0  # Or raise an exception, depending on desired behavior

    # Simulate monthly sales data (replace with actual data retrieval)
    if month == 0:
        return 100
    elif month == 1:
        return 150
    elif month == 2:
        return 200
    else:
        return 50  # Default sales value for other months


def calculate_quarterly_sales() -> int:
    """
    Calculates the total sales for the first quarter (January, February, March).

    Returns:
        The total sales for the first quarter.
    """

    sum: int = 0  # Initialize sum to 0
    for i in range(3):  # Iterate through the first three months (0, 1, 2)
        monthly_sales = getMonthlySales(i)

        # Check for potential overflow before adding.  Using a wider type (int)
        # is sufficient here because we're only summing three relatively small values.
        # For larger sums or larger individual sales values, consider using `decimal.Decimal`
        # for arbitrary-precision arithmetic.
        if sum > sys.maxsize - monthly_sales:
            print("Error: Potential integer overflow detected!", file=sys.stderr)
            return -1  # Indicate an error

        sum += monthly_sales

    return sum


if __name__ == "__main__":
    total_sales = calculate_quarterly_sales()

    if total_sales != -1:
        # Specify output encoding (UTF-8 is a good default)
        print(f"Total sales for the first quarter: {total_sales}", file=sys.stdout, flush=True)
    else:
        print("Error calculating total sales.", file=sys.stderr)

