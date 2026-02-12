import secrets

def calculate_total_sales(sales_jan, sales_feb, sales_mar):
    """
    Calculates the total sales for three months.

    Args:
        sales_jan: Sales for January (numeric).
        sales_feb: Sales for February (numeric).
        sales_mar: Sales for March (numeric).

    Returns:
        The total sales for the three months.  Returns None if any input is invalid.
    """

    if not all(isinstance(sale, (int, float)) for sale in [sales_jan, sales_feb, sales_mar]):
        print("Error: Sales values must be numeric.")
        return None  # Handle invalid input gracefully

    if any(sale < 0 for sale in [sales_jan, sales_feb, sales_mar]):
        print("Error: Sales values cannot be negative.")
        return None

    total_sales = 0.0  # Initialize as float for accurate calculations
    total_sales += sales_jan
    total_sales += sales_feb
    total_sales += sales_mar

    return total_sales


def main():
    """
    Main function to demonstrate sales calculation.
    """

    # Generate random sales data for demonstration purposes.  In a real application,
    # these would come from a database, user input, or other reliable source.
    # Using secrets.randbelow for cryptographically secure random numbers.
    sales_jan = secrets.randbelow(10000)  # Sales for January (up to 9999)
    sales_feb = secrets.randbelow(12000)  # Sales for February (up to 11999)
    sales_mar = secrets.randbelow(11000)  # Sales for March (up to 10999)

    total_sales = calculate_total_sales(sales_jan, sales_feb, sales_mar)

    if total_sales is not None:
        print(f"Total sales for the quarter: ${total_sales:.2f}")  # Format to 2 decimal places


if __name__ == "__main__":
    main()

