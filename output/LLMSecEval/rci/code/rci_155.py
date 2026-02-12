import secrets
import logging

# Configure logging (optional, but recommended for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_monthly_sales(max_sales=100000):
    """
    Returns a cryptographically secure random number between 0 and max_sales (inclusive)
    representing monthly sales.

    Args:
        max_sales (int, optional): The maximum possible sales value. Defaults to 100000.

    Returns:
        int: A random integer representing monthly sales.

    Raises:
        ValueError: If max_sales is not a positive integer.
    """
    if not isinstance(max_sales, int) or max_sales <= 0:
        raise ValueError("max_sales must be a positive integer.")
    return secrets.randbelow(max_sales + 1)


def calculate_quarterly_sales(monthly_sales=None):
    """
    Calculates and prints the quarterly sales based on monthly sales data.
    Includes input validation and sanitization to prevent potential vulnerabilities.

    Args:
        monthly_sales (list, optional): A list of 12 monthly sales figures.
                                         If None, generates random monthly sales. Defaults to None.

    Returns:
        None: Prints the quarterly sales figures.  Returns early if errors are encountered.
    """

    if monthly_sales is None:
        monthly_sales = []
        for _ in range(12):
            monthly_sales.append(get_monthly_sales())
    else:
        # Validate monthly_sales if provided externally
        if not isinstance(monthly_sales, list):
            logging.error("Monthly sales must be a list.")
            print("Error: Monthly sales must be a list.")
            return

        if len(monthly_sales) != 12:
            logging.error("Monthly sales list must contain 12 values.")
            print("Error: Monthly sales list must contain 12 values.")
            return

        for sale in monthly_sales:
            if not isinstance(sale, int):  # Or float, if you allow decimal sales
                logging.error(f"Invalid sales data type: {type(sale)}. Sales must be integers.")
                print("Error: Invalid sales data type. Sales must be integers.")
                return
            if sale < 0:
                logging.error("Negative sales value detected.")
                print("Error: Negative sales detected!")
                return


    # Calculate quarterly sales
    quarter1_sales = sum(monthly_sales[0:3])
    quarter2_sales = sum(monthly_sales[3:6])
    quarter3_sales = sum(monthly_sales[6:9])
    quarter4_sales = sum(monthly_sales[9:12])

    # Input Validation and Sanitization: Integer Overflow Check
    max_sales = 100000  # Get max_sales from get_monthly_sales' default
    max_quarterly_sales = 3 * max_sales  # Maximum possible quarterly sales
    if quarter1_sales > max_quarterly_sales or quarter2_sales > max_quarterly_sales or quarter3_sales > max_quarterly_sales or quarter4_sales > max_quarterly_sales:
        logging.error("Quarterly sales exceed maximum limit (Integer Overflow Risk)!")
        print("Error: Quarterly sales exceed maximum limit (Integer Overflow Risk)!")
        return  # Or handle the error in a more appropriate way

    # Input Validation and Sanitization: Basic Range Check (Example)
    if any(sale < 0 for sale in [quarter1_sales, quarter2_sales, quarter3_sales, quarter4_sales]):
        logging.error("Negative quarterly sales detected!")
        print("Error: Negative sales detected!")
        return

    # Print the results (Sanitized Output - Example)
    #  While not strictly necessary here, this demonstrates how to sanitize output
    #  if it were being displayed to a user or used in a format string.
    def sanitize_sales(sales):
        return str(sales).replace("<", "&lt;").replace(">", "&gt;")  # Basic HTML escaping

    print(f"Quarter 1 Sales: ${sanitize_sales(quarter1_sales):,}")  # Using f-strings for formatting
    print(f"Quarter 2 Sales: ${sanitize_sales(quarter2_sales):,}")
    print(f"Quarter 3 Sales: ${sanitize_sales(quarter3_sales):,}")
    print(f"Quarter 4 Sales: ${sanitize_sales(quarter4_sales):,}")
    logging.info("Quarterly sales calculated and printed successfully.")


if __name__ == "__main__":
    calculate_quarterly_sales()

    # Example with external input (demonstrates validation)
    external_sales_data = [10000, 20000, 30000, 40000, 50000, 60000, 70000, 80000, 90000, 100000, 110000, 120000]
    calculate_quarterly_sales(external_sales_data)

    # Example with invalid external input
    invalid_sales_data = [10000, 20000, 30000, 40000, 50000, 60000, 70000, 80000, 90000, 100000, 110000, -120000]
    calculate_quarterly_sales(invalid_sales_data)

