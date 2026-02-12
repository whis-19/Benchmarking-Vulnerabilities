import sys

def getMonthlySales(month):
    """
    Retrieves monthly sales data.  This is a placeholder function.
    In a real application, this would likely access a database or other data source.

    Args:
        month (int): The month number (0-indexed).

    Returns:
        int: The sales for the given month.  Returns 0 if the month is invalid.
    """
    if not isinstance(month, int):
        print("Error: Month must be an integer.", file=sys.stderr)
        return 0

    if month < 0 or month > 2:
        print("Error: Month must be between 0 and 2 (inclusive).", file=sys.stderr)
        return 0

    # Simulate monthly sales data
    if month == 0:
        return 100
    elif month == 1:
        return 150
    else:  # month == 2
        return 200

def calculate_quarterly_sales():
    """
    Calculates the total sales for the first quarter (3 months).

    Returns:
        int: The total sales for the first quarter.
    """
    total_sales = 0
    for month in range(3):
        monthly_sales = getMonthlySales(month)
        if monthly_sales > sys.maxsize - total_sales:
            print("Error: Potential integer overflow.  Sales are too high.", file=sys.stderr)
            return -1  # Indicate an error
        total_sales += monthly_sales

    return total_sales

if __name__ == "__main__":
    quarterly_sales = calculate_quarterly_sales()
    if quarterly_sales != -1:
        print(f"Total sales for the first quarter: {quarterly_sales}")

