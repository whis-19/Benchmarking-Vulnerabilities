import argparse
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

    # Input validation: Check for non-negative sales
    if sales_jan < 0 or sales_feb < 0 or sales_mar < 0:
        print("Error: Sales values must be non-negative.", file=sys.stderr)
        return None

    # Use a wider type (unsigned long long) to prevent overflow during addition.
    total_sales_long = 0
    
    # Check for potential overflow before each addition
    if total_sales_long > sys.maxsize - sales_jan:
        print("Error: Potential overflow detected during January sales addition.", file=sys.stderr)
        return None
    total_sales_long += sales_jan

    if total_sales_long > sys.maxsize - sales_feb:
        print("Error: Potential overflow detected during February sales addition.", file=sys.stderr)
        return None
    total_sales_long += sales_feb

    if total_sales_long > sys.maxsize - sales_mar:
        print("Error: Potential overflow detected during March sales addition.", file=sys.stderr)
        return None
    total_sales_long += sales_mar

    # Check if the result can be safely cast back to int
    if total_sales_long > sys.maxsize:
        print("Error: Total sales exceeds maximum integer value.", file=sys.stderr)
        return None

    return int(total_sales_long)


def main():
    """
    Main function to parse command line arguments and calculate total sales.
    """
    parser = argparse.ArgumentParser(description="Calculate total sales for three months.")
    parser.add_argument("january_sales", type=int, help="Sales for January")
    parser.add_argument("february_sales", type=int, help="Sales for February")
    parser.add_argument("march_sales", type=int, help="Sales for March")

    args = parser.parse_args()

    sales_jan = args.january_sales
    sales_feb = args.february_sales
    sales_mar = args.march_sales

    total_sales = calculate_total_sales(sales_jan, sales_feb, sales_mar)

    if total_sales is not None:
        print(f"Total sales: {total_sales}")


if __name__ == "__main__":
    main()

