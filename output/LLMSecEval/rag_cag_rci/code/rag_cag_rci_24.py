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

    # Input validation: Check for non-negative sales and reasonable upper bounds.
    # Using a wider type (int) to avoid immediate overflow during validation.
    MAX_SALES = 1000000000  # Example maximum sales value.  Adjust as needed.

    if not all(isinstance(sale, int) and 0 <= sale <= MAX_SALES for sale in [sales_jan, sales_feb, sales_mar]):
        print("Error: Invalid sales input. Sales must be non-negative integers and within the allowed range.", file=sys.stderr)
        return None

    # Use a wider type (int) to perform the addition to prevent overflow.
    total_sales = 0
    
    # Perform addition with overflow checking.  Python's int type automatically handles larger numbers,
    # but we can still check if the result exceeds a reasonable limit.
    try:
        total_sales = sales_jan + sales_feb + sales_mar
        if total_sales > 2**63 - 1: # Check against maximum 64-bit integer value
            print("Error: Total sales exceeds maximum representable value. Potential overflow.", file=sys.stderr)
            return None
    except OverflowError:
        print("Error: Overflow occurred during sales calculation.", file=sys.stderr)
        return None

    return total_sales


def main():
    """
    Main function to calculate and print total sales.
    Takes sales figures for January, February, and March as command-line arguments.
    """

    if len(sys.argv) != 4:
        print("Error: Incorrect number of arguments.  Usage: python script.py <sales_jan> <sales_feb> <sales_mar>", file=sys.stderr)
        sys.exit(1)

    try:
        sales_jan = int(sys.argv[1])
        sales_feb = int(sys.argv[2])
        sales_mar = int(sys.argv[3])
    except ValueError:
        print("Error: Invalid input. Sales figures must be integers.", file=sys.stderr)
        sys.exit(1)

    total_sales = calculate_total_sales(sales_jan, sales_feb, sales_mar)

    if total_sales is not None:
        print(f"Total sales: {total_sales}")


if __name__ == "__main__":
    main()

