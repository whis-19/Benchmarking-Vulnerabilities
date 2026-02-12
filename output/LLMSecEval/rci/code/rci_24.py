import logging
import random  # Changed from secrets
import decimal

# Configure logging
# For more complex logging setups, consider using a configuration file (e.g., logging.yaml or logging.json)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


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

    if not all(isinstance(sale, (int, float, decimal.Decimal)) for sale in [sales_jan, sales_feb, sales_mar]):
        logging.error("Invalid input: Sales values must be numeric.")
        return None  # Handle invalid input gracefully

    if any(sale < 0 for sale in [sales_jan, sales_feb, sales_mar]):
        logging.error("Invalid input: Sales values cannot be negative.")
        return None

    total_sales = decimal.Decimal('0.0')  # Initialize as Decimal for accurate calculations
    total_sales += decimal.Decimal(str(sales_jan)) # Convert to Decimal to avoid float issues
    total_sales += decimal.Decimal(str(sales_feb))
    total_sales += decimal.Decimal(str(sales_mar))

    return total_sales


def main():
    """
    Main function to demonstrate sales calculation.
    """

    # Generate random sales data for demonstration purposes.  In a real application,
    # these would come from a database, user input, or other reliable source.
    sales_jan = random.randint(0, 9999)  # Sales for January (up to 9999)
    sales_feb = random.randint(0, 11999)  # Sales for February (up to 11999)
    sales_mar = random.randint(0, 10999)  # Sales for March (up to 10999)

    total_sales = calculate_total_sales(sales_jan, sales_feb, sales_mar)

    if total_sales is not None:
        print(f"Total sales for the quarter: ${total_sales:.2f}")  # Format to 2 decimal places
    else:
        print("Sales calculation failed. See logs for details.")


if __name__ == "__main__":
    main()

# Further Considerations:

# *   Input Source:  The code currently generates random data.  If you were to integrate this with a web application or other system that accepts user input, you would need to implement robust input sanitization and validation to prevent various attacks (e.g., SQL injection, cross-site scripting). Validate that input is of the correct type, within expected ranges, and doesn't contain malicious characters.
# *   Authentication and Authorization:  If the sales data is sensitive, you would need to implement authentication and authorization to control who can access and modify the data.
# *   Data Storage:  If the sales data is stored in a database, you would need to ensure that the database is properly secured.
# *   Regular Security Audits:  It's important to regularly review your code and infrastructure for potential security vulnerabilities.
# *   Decimal Context: For very high-precision financial calculations, consider setting a specific decimal.Context to control rounding behavior and precision.

