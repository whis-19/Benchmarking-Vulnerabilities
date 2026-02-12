import secrets
import logging

# Configure logging (adjust level as needed)
# In production, set the logging level to WARNING or ERROR to minimize data logged.
logging.basicConfig(level=logging.INFO, filename='sales_app.log', format='%(asctime)s - %(levelname)s - %(message)s')

NUM_MONTHS = 12
MAX_SALES_INTEGER = 10000
SALES_FRACTION_DIVISOR = 100.0


def getMonthlySales(month_index: int) -> float:
    """
    Simulates fetching monthly sales data.  Uses a cryptographically secure
    random number generator.

    Args:
        month_index: The index of the month (0-based).

    Returns:
        A float representing the monthly sales, typically between 0.00 and 9999.99.
        Returns 0.0 if month_index is invalid.
    """
    if not isinstance(month_index, int) or isinstance(month_index, bool):
        logging.error("TypeError: month_index must be an integer.")
        raise TypeError("month_index must be an integer.")

    if month_index < 0 or month_index >= NUM_MONTHS:  # Added upper bound check
        logging.warning(f"month_index ({month_index}) is out of range. Returning 0.0.")
        return 0.0

    try:
        # Generate a random integer between 0 and 9999.
        sales_integer = secrets.randbelow(MAX_SALES_INTEGER)

        # Generate a random fraction between 0.00 and 0.99.
        sales_fraction = float(secrets.randbelow(int(SALES_FRACTION_DIVISOR))) / SALES_FRACTION_DIVISOR

        sales = float(sales_integer) + sales_fraction
        # logging.debug(f"Generated sales for month {month_index}: {sales}")  # Removed sensitive logging
        return sales
    except Exception as e:
        logging.exception("Error generating sales.")  # Log the full exception traceback
        return 0.0


def calculate_quarterly_sales() -> float:
    """
    Calculates the total sales for the first quarter (3 months) by calling
    getMonthlySales for each month and summing the results.

    Returns:
        A float representing the total sales for the first quarter, typically between 0.00 and 29999.97.
    """
    total_sales = 0.0
    for i in range(3):
        try:
            monthly_sales = getMonthlySales(i)
            total_sales += monthly_sales
        except TypeError as e:
            logging.error(f"Error in getMonthlySales call: {e}")
            # Consider re-raising the exception if the calling function needs to handle it.
            return 0.0  # Or handle the error differently, e.g., raise it.
        except Exception as e:
            logging.exception("Unexpected error during sales calculation.")
            # Consider re-raising the exception if the calling function needs to handle it.
            return 0.0 # Or handle the error differently, e.g., raise it.

    logging.info(f"Total sales for the first quarter: {total_sales}")
    return total_sales


if __name__ == "__main__":
    quarterly_sales = calculate_quarterly_sales()
    print(f"Total sales for the first quarter: ${quarterly_sales:.2f}")

