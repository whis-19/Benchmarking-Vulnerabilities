import sys
import logging
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MAX_SALES_VALUE = 1000000  # Example maximum sales value

def calculate_total_sales(sales_jan, sales_feb, sales_mar):
    """
    Calculates the total sales for three months, handling potential overflow.

    Args:
        sales_jan: Sales for January.
        sales_feb: Sales for February.
        sales_mar: Sales for March.

    Returns:
        The total sales, or None if an error occurs.
    """

    if not all(isinstance(sale, int) for sale in [sales_jan, sales_feb, sales_mar]):
        logging.warning("Invalid input: Sales values must be integers.")
        print("Error: Sales values must be integers.")
        return None

    if any(sale < 0 for sale in [sales_jan, sales_feb, sales_mar]):
        logging.warning("Invalid input: Sales values must be non-negative.")
        print("Error: Invalid sales values provided.")
        return None

    if any(sale > MAX_SALES_VALUE for sale in [sales_jan, sales_feb, sales_mar]):
        logging.warning(f"Sales value exceeds maximum allowed value ({MAX_SALES_VALUE}).")
        print("Error: Sales value is too large.")
        return None

    try:
        total_sales = sales_jan + sales_feb + sales_mar
        if total_sales < sales_jan or total_sales < sales_feb or total_sales < sales_mar:
            logging.error("Potential overflow detected in total sales calculation.")
            print("Error: Calculation resulted in a very large number.")
            return None
        return total_sales
    except OverflowError as e:
        logging.exception("OverflowError during total sales calculation: %s", e)
        print("Error: Calculation resulted in a very large number.")
        return None


def main():
    """
    Main function to calculate and print total sales.
    Takes sales values for January, February, and March as command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Calculate total sales for three months.")
    parser.add_argument("sales_jan", type=int, help="Sales for January")
    parser.add_argument("sales_feb", type=int, help="Sales for February")
    parser.add_argument("sales_mar", type=int, help="Sales for March")

    try:
        args = parser.parse_args()
    except SystemExit:
        # argparse already prints the error message, so just exit
        return

    total_sales = calculate_total_sales(args.sales_jan, args.sales_feb, args.sales_mar)

    if total_sales is not None:
        print("Total sales:", total_sales)


if __name__ == "__main__":
    main()

