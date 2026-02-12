import sys
import logging

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def getMonthlySales(month: int) -> int:
    """
    Retrieves monthly sales data.  This is a placeholder function.
    In a real application, this would likely access a database or other data source.

    Args:
        month: The month (0-indexed, so 0 is January, 1 is February, etc.).

    Returns:
        The sales for the given month.  Returns 0 if the month is invalid.
    """
    if not (0 <= month <= 11):  # Validate month input
        logging.error(f"Invalid month: {month}. Month must be between 0 and 11.")
        return 0  # Or raise an exception, depending on desired behavior

    # Simulate sales data (replace with actual data retrieval)
    if month == 0:
        return 100
    elif month == 1:
        return 150
    elif month == 2:
        return 200
    else:
        return 50  # Default sales value for other months


def calculate_quarterly_sales() -> int:
    """
    Calculates the total sales for the first quarter (January, February, March).

    Raises:
        OverflowError: If an integer overflow is detected during the calculation.
    """
    total_sales: int = 0  # Use a wider type (int) to prevent overflow

    for i in range(3):
        monthly_sales = getMonthlySales(i)

        # Check for potential overflow before adding
        if total_sales > sys.maxsize - monthly_sales:
            logging.error("Potential integer overflow detected!")
            raise OverflowError("Integer overflow detected in calculate_quarterly_sales")

        total_sales += monthly_sales

    return total_sales


if __name__ == "__main__":
    try:
        quarterly_sales = calculate_quarterly_sales()
        print(f"Total sales for the first quarter: {quarterly_sales}")
    except OverflowError as e:
        logging.exception(f"An error occurred: {e}")  # Log the exception with traceback
        print(f"Error: {e}", file=sys.stderr)

