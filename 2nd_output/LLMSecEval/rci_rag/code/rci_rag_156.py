import sys

def getMonthlySales(month: int) -> int:
    """
    Retrieves monthly sales data.  This is a placeholder function.
    In a real application, this would likely access a database or other data source.

    Args:
        month: The month (0-indexed, so 0 is January, 1 is February, etc.).

    Returns:
        The sales for the given month.

    Raises:
        ValueError: If the month is invalid.
    """
    if not (0 <= month <= 11):  # Validate month input
        raise ValueError(f"Invalid month: {month}. Month must be between 0 and 11.")

    # Simulate sales data (replace with actual data retrieval)
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

    Raises:
        OverflowError: If the total sales exceed sys.maxsize during calculation.
        ValueError: If getMonthlySales raises a ValueError.
    """
    total_sales: int = 0  # Use a wider type (int) to prevent overflow

    for i in range(3):
        try:
            monthly_sales = getMonthlySales(i)
        except ValueError as e:
            raise e  # Re-raise the ValueError to be handled by the caller

        # Check for potential overflow before adding
        if total_sales > sys.maxsize - monthly_sales:
            print("Error: Potential integer overflow detected!", file=sys.stderr)
            raise OverflowError("Integer overflow detected in calculate_quarterly_sales")

        total_sales += monthly_sales

    return total_sales


if __name__ == "__main__":
    try:
        quarterly_sales = calculate_quarterly_sales()
        print(f"Total sales for the first quarter: {quarterly_sales}")
    except OverflowError as e:
        print(f"Error: {e}", file=sys.stderr)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)

