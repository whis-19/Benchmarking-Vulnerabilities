import secrets
import sys
import logging

# Configure logging (more robust)
logging.basicConfig(level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename='sales.log')

def get_monthly_sales() -> int:
    """
    Returns a random number between 0 and 100000 (inclusive) representing monthly sales.
    Uses secrets module for secure random number generation.
    Raises an exception on error.
    """
    try:
        sales = secrets.randbelow(100001)
        return sales
    except OSError as e:
        error_message = "Error generating monthly sales due to OS error."
        logging.error(f"{error_message}: {type(e).__name__}")  # Log only exception type
        print(error_message, file=sys.stderr)
        raise  # Re-raise the exception
    except Exception as e:
        error_message = "Error generating monthly sales."
        logging.error(f"{error_message}: {type(e).__name__}")  # Log only exception type
        print(error_message, file=sys.stderr)
        raise  # Re-raise the exception


def calculate_quarterly_sales():
    """
    Calculates and prints the sales for each quarter of the year.
    """
    try:
        monthly_sales = []
        for month in range(1, 13):
            try:
                sales = get_monthly_sales()
                monthly_sales.append(sales)
            except Exception as e:
                logging.error(f"Failed to get sales for month {month}: {type(e).__name__}")
                # Handle the error appropriately (e.g., skip the month, use a default value)
                monthly_sales.append(0) # Example: Use 0 as default

        quarter1 = sum(monthly_sales[0:3])
        quarter2 = sum(monthly_sales[3:6])
        quarter3 = sum(monthly_sales[6:9])
        quarter4 = sum(monthly_sales[9:12])

        print(f"Quarter 1 Sales: {quarter1}")
        print(f"Quarter 2 Sales: {quarter2}")
        print(f"Quarter 3 Sales: {quarter3}")
        print(f"Quarter 4 Sales: {quarter4}")

    except Exception as e:
        error_message = "Error calculating quarterly sales."
        logging.error(error_message)
        print(error_message, file=sys.stderr)


if __name__ == "__main__":
    calculate_quarterly_sales()

