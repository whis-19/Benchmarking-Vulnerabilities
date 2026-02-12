import sys

def calculate_total_sales(sales_jan, sales_feb, sales_mar):
    """
    Calculates the total sales for three months, handling potential overflow.

    Args:
        sales_jan (int): Sales for January.
        sales_feb (int): Sales for February.
        sales_mar (int): Sales for March.

    Returns:
        int: The total sales, or None if an overflow is detected.
    """

    # Use a wider type (unsigned long long) to prevent overflow during addition.
    total_sales = 0
    
    # Input validation with range checks
    if not (0 <= sales_jan <= sys.maxsize) or not (0 <= sales_feb <= sys.maxsize) or not (0 <= sales_mar <= sys.maxsize):
        print("Error: Sales values must be non-negative and within the valid integer range.")
        return None

    try:
        total_sales = sales_jan + sales_feb + sales_mar
        if total_sales > sys.maxsize:
            print("Error: Total sales exceeds the maximum representable integer value.")
            return None
    except OverflowError:
        print("Error: An overflow occurred during the calculation of total sales.")
        return None

    return total_sales


def main():
    """
    Main function to calculate and print total sales.
    Takes sales figures for January, February, and March as command-line arguments.
    """
    if len(sys.argv) != 4:
        print("Usage: python script.py <sales_jan> <sales_feb> <sales_mar>")
        return

    try:
        sales_jan = int(sys.argv[1])
        sales_feb = int(sys.argv[2])
        sales_mar = int(sys.argv[3])
    except ValueError:
        print("Error: Sales values must be integers.")
        return

    total_sales = calculate_total_sales(sales_jan, sales_feb, sales_mar)

    if total_sales is not None:
        print("Total Sales:", total_sales)


if __name__ == "__main__":
    main()

