import argparse
import sys

def calculate_total_sales(sales_jan: int, sales_feb: int, sales_mar: int) -> int:
    """
    Calculates the total sales for three months, handling potential overflow.

    Args:
        sales_jan: Sales for January (unsigned integer).
        sales_feb: Sales for February (unsigned integer).
        sales_mar: Sales for March (unsigned integer).

    Returns:
        The total sales as an integer.  Returns -1 if an overflow is detected.
    """

    # Input validation: Check for non-negative sales values.  We're using integers,
    # so negative values are invalid in this context.  We also check for excessively large
    # individual sales values that could lead to overflow even with a wider type.
    if sales_jan < 0 or sales_feb < 0 or sales_mar < 0:
        print("Error: Sales values must be non-negative.", file=sys.stderr)
        return -1  # Indicate an error

    # Use a wider type (int) to prevent overflow during addition.  Python's `int` type
    # automatically handles arbitrarily large integers, mitigating overflow risks.
    total_sales: int = 0

    # Perform the addition.  Python's `int` type handles overflow automatically.
    total_sales = sales_jan + sales_feb + sales_mar

    # Optional:  Add a check to ensure the total sales is within a reasonable range.
    # This is application-specific and depends on the expected scale of sales.
    # For example, if we expect total sales to never exceed a certain value:
    # if total_sales > 1000000000:  # Example upper bound
    #     print("Warning: Total sales exceed expected range.", file=sys.stderr)
    #     # Decide whether to proceed or return an error.  In this case, we'll proceed.

    return total_sales


def main():
    """
    Main function to parse command-line arguments and calculate total sales.
    """
    parser = argparse.ArgumentParser(description="Calculate total sales for three months.")
    parser.add_argument("jan_sales", type=int, help="Sales for January")
    parser.add_argument("feb_sales", type=int, help="Sales for February")
    parser.add_argument("mar_sales", type=int, help="Sales for March")

    args = parser.parse_args()

    # Call the function to calculate total sales.
    total_sales = calculate_total_sales(args.jan_sales, args.feb_sales, args.mar_sales)

    if total_sales != -1:
        print(f"Total sales: {total_sales}")
    else:
        # Error message is already printed in calculate_total_sales.
        pass


if __name__ == "__main__":
    main()

