import sys

def calculate_total_sales(sales_jan, sales_feb, sales_mar):
    """
    Calculates the total sales for three months, handling potential overflow.

    Args:
        sales_jan (int): Sales for January.
        sales_feb (int): Sales for February.
        sales_mar (int): Sales for March.

    Returns:
        int: The total sales, or None if an overflow is detected.  Prints an error message to stderr if overflow occurs.
    """

    # Input validation: Check for non-negative sales and reasonable limits.
    # Using a wider type (long) for intermediate calculations to prevent overflow.
    sales_jan = int(sales_jan)
    sales_feb = int(sales_feb)
    sales_mar = int(sales_mar)

    if sales_jan < 0 or sales_feb < 0 or sales_mar < 0:
        print("Error: Sales values must be non-negative.", file=sys.stderr)
        return None

    # Define a maximum reasonable sales value to prevent extremely large numbers.
    MAX_SALES = 1000000000  # Example: 1 billion

    if sales_jan > MAX_SALES or sales_feb > MAX_SALES or sales_mar > MAX_SALES:
        print("Error: Sales values exceed maximum allowed value.", file=sys.stderr)
        return None

    # Use a wider type (long) for intermediate calculations to prevent overflow.
    total_sales = int(sales_jan) + int(sales_feb) + int(sales_mar)

    # Check for potential overflow after addition.  Python automatically promotes to long,
    # so we need to check if the result is larger than the maximum integer value.
    import sys
    max_int = sys.maxsize

    if total_sales > max_int:
        print("Error: Total sales exceeds maximum representable integer value (overflow).", file=sys.stderr)
        return None

    return int(total_sales)


def main():
    """
    Main function to calculate and print total sales.  Takes sales values as command-line arguments.
    """
    if len(sys.argv) != 4:
        print("Usage: python script.py <sales_jan> <sales_feb> <sales_mar>", file=sys.stderr)
        sys.exit(1)

    try:
        sales_jan = int(sys.argv[1])
        sales_feb = int(sys.argv[2])
        sales_mar = int(sys.argv[3])
    except ValueError:
        print("Error: Sales values must be integers.", file=sys.stderr)
        sys.exit(1)

    total_sales = calculate_total_sales(sales_jan, sales_feb, sales_mar)

    if total_sales is not None:
        print(f"Total sales: {total_sales}")


if __name__ == "__main__":
    main()

