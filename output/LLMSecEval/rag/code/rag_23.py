import sys

def getMonthlySales(month: int) -> int:
    """
    Retrieves monthly sales data.  This is a placeholder and should be replaced
    with actual data retrieval logic.  Includes input validation to prevent
    out-of-bounds access.

    Args:
        month: The month (0-indexed, so 0 is January, 1 is February, etc.).

    Returns:
        The sales for the given month.  Returns 0 if the month is invalid.
    """
    if not isinstance(month, int):
        print("Error: Month must be an integer.", file=sys.stderr)
        return 0

    if month < 0 or month > 11:  # Validate month range (0-11)
        print(f"Error: Invalid month: {month}. Month must be between 0 and 11.", file=sys.stderr)
        return 0

    # Placeholder sales data (replace with actual data source)
    monthly_sales = [100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210]
    return monthly_sales[month]


def calculate_quarterly_sales() -> int:
    """
    Calculates the total sales for the first quarter (January, February, March).
    Uses a wider type (int) to prevent potential overflow.  Includes overflow
    checking.
    """
    total_sales: int = 0  # Use a wider type (int)

    for i in range(3):
        monthly_sale = getMonthlySales(i)
        if monthly_sale < 0:
            print(f"Error: Invalid sales value {monthly_sale} for month {i}.", file=sys.stderr)
            return -1 # Indicate an error

        # Overflow check before addition
        if total_sales > sys.maxsize - monthly_sale:
            print("Error: Potential integer overflow detected.", file=sys.stderr)
            return -1 # Indicate an error

        total_sales += monthly_sale

    return total_sales


def main():
    """
    Main function to execute the quarterly sales calculation and print the result.
    """
    quarterly_sales = calculate_quarterly_sales()

    if quarterly_sales >= 0:
        print(f"Total sales for the first quarter: {quarterly_sales}")
    else:
        print("Error: Could not calculate quarterly sales.", file=sys.stderr)


if __name__ == "__main__":
    main()

