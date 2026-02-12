import secrets

def sanitize_sales(sale):
    """Sanitizes a single sales value."""
    try:
        sale = float(sale)  # Attempt to convert to float
    except (ValueError, TypeError):
        raise TypeError("Sales values must be numeric or convertible to numeric.")

    if sale < 0:
        raise ValueError("Sales values cannot be negative.")
    return sale


def calculate_total_sales(sales_jan, sales_feb, sales_mar):
    """
    Calculates the total sales for three months.  Sanitizes input.

    Args:
        sales_jan: Sales for January (numeric value or string).
        sales_feb: Sales for February (numeric value or string).
        sales_mar: Sales for March (numeric value or string).

    Returns:
        The total sales for the three months.

    Raises:
        TypeError: If any input cannot be converted to a number.
        ValueError: If any input is negative.
    """

    try:
        sales_jan = sanitize_sales(sales_jan)
        sales_feb = sanitize_sales(sales_feb)
        sales_mar = sanitize_sales(sales_mar)
    except (TypeError, ValueError) as e:
        raise e  # Re-raise the exception to be caught in main

    total_sales = 0.0
    total_sales += sales_jan
    total_sales += sales_feb
    total_sales += sales_mar
    return total_sales


def main():
    """
    Calculates and prints the total sales for January, February, and March.
    """

    # Generate random sales data for demonstration (replace with actual data)
    sales_jan = secrets.randbelow(10000)  # Up to 9999
    sales_feb = secrets.randbelow(12000)
    sales_mar = secrets.randbelow(11000)

    try:
        total_sales = calculate_total_sales(sales_jan, sales_feb, sales_mar)
        print(f"Total sales: ${total_sales:.2f}")  # Format to 2 decimal places
    except TypeError as e:
        print(f"Error: Invalid input type: {e}")
    except ValueError as e:
        print(f"Error: Invalid input value: {e}")


if __name__ == "__main__":
    main()

