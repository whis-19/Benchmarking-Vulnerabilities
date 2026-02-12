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
    if 0 <= month <= 2:
        # Simulate sales data.  Replace with actual data retrieval.
        if month == 0:
            return 100
        elif month == 1:
            return 150
        else:
            return 200
    else:
        return 0  # Handle out-of-bounds month

def calculate_quarterly_sales():
    """
    Calculates the total sales for the first quarter (months 0, 1, and 2).

    Returns:
        int: The total sales for the first quarter.  Returns -1 if an overflow occurs.
    """
    total_sales = 0
    for i in range(3):
        # Input validation for getMonthlySales parameter
        if not (0 <= i <= 2):
            print("Error: Month index out of range.", file=sys.stderr)
            return -1  # Indicate an error

        monthly_sales = getMonthlySales(i)

        # Check for potential overflow before adding
        if total_sales > sys.maxsize - monthly_sales:
            print("Error: Integer overflow detected.", file=sys.stderr)
            return -1  # Indicate an error

        total_sales += monthly_sales

    return total_sales

if __name__ == "__main__":
    quarterly_sales = calculate_quarterly_sales()

    if quarterly_sales != -1:
        print(f"Total sales for the first quarter: {quarterly_sales}")
    else:
        print("Error occurred during sales calculation.", file=sys.stderr)

