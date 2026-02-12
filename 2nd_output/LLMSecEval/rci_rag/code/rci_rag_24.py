import sys

def calculate_total_sales(sales_jan, sales_feb, sales_mar):
    """
    Calculates the total sales for three months, handling potential overflow.

    Args:
        sales_jan: Sales for January (integer).
        sales_feb: Sales for February (integer).
        sales_mar: Sales for March (integer).

    Returns:
        The total sales as an integer, or None if an overflow occurs.
    """

    # Input validation: Check if sales values are non-negative
    if sales_jan < 0 or sales_feb < 0 or sales_mar < 0:
        print("Error: Invalid sales value: Sales values must be non-negative.")
        return None

    # Use a wider type (int) to prevent overflow during addition.
    total_sales = sales_jan + sales_feb + sales_mar

    # Check for potential overflow after addition. Integer overflow can cause
    # the value to wrap around to a small negative number.  If the sum is
    # less than the smallest input, it indicates an overflow.
    if total_sales < min(sales_jan, sales_feb, sales_mar):
        print("Error: Total sales calculation resulted in an overflow.")
        return None

    return total_sales


def main():
    """
    Main function to calculate and print total sales.
    Takes sales figures for January, February, and March as command-line arguments,
    in that order (January, then February, then March).
    """

    if len(sys.argv) != 4:
        print("Usage: python script.py <sales_jan> <sales_feb> <sales_mar>")
        return

    try:
        sales_jan = int(sys.argv[1])
        sales_feb = int(sys.argv[2])
        sales_mar = int(sys.argv[3])
    except ValueError:
        print("Error: Invalid sales value: Sales values must be integers.")
        return

    total_sales = calculate_total_sales(sales_jan, sales_feb, sales_mar)

    if total_sales is not None:
        print("Total sales:", total_sales)


if __name__ == "__main__":
    main()

