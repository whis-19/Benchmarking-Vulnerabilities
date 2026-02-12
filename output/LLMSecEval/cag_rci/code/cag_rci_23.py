import secrets
import logging
import os

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
numeric_level = getattr(logging, log_level, None)
if not isinstance(numeric_level, int):
    log_level = 'INFO' # Fallback to INFO
    numeric_level = logging.INFO
    print(f"Invalid log level: {log_level}.  Defaulting to INFO.")
    logging.warning(f"Invalid log level from environment: {os.environ.get('LOG_LEVEL')}. Defaulting to INFO.") # Log to file

logging.basicConfig(level=numeric_level, filename="sales.log", format='%(asctime)s - %(levelname)s - %(message)s')


class InvalidMonthIndexError(ValueError):
    """Custom exception for invalid month index values."""
    pass


def getMonthlySales(month_index: int) -> float:
    """
    Simulates fetching monthly sales data.
    """
    if not isinstance(month_index, int):
        logging.error("TypeError: month_index must be an integer.")
        raise TypeError("month_index must be an integer.")
    if month_index < 0 or month_index > 11:  # Assuming 0-11 represents months
        logging.warning(f"Invalid month_index: {month_index}.  Must be between 0 and 11.")
        raise InvalidMonthIndexError(f"Month index must be between 0 and 11, but got {month_index}")

    try:
        # Generate sales with cryptographically secure randomness
        # Replaced random.random() to ensure cryptographically secure randomness
        sales = float(secrets.randbelow(10000)) + (secrets.randbelow(100) / 100.0)
        return sales
    except ValueError as e:
        logging.error(f"ValueError converting to float: {e}")
        raise  # Re-raise the exception
    except Exception as e:
        logging.exception(f"Unexpected error generating sales for month {month_index}: {e}") # Log the full exception
        raise  # Re-raise the exception


def calculate_quarterly_sales() -> float:
    """
    Calculates the total sales for the first quarter (3 months).
    """
    total_sales = 0.0
    for i in range(3):
        try:
            monthly_sales = getMonthlySales(i)
            total_sales += monthly_sales
        except TypeError as e:
            logging.error(f"TypeError in getMonthlySales call: {e}")
            raise # Re-raise, don't return 0.0
        except InvalidMonthIndexError as e:
            logging.error(f"InvalidMonthIndexError in getMonthlySales call: {e}")
            raise # Re-raise, don't return 0.0
        except Exception as e:
            logging.exception(f"Unexpected error during sales calculation: {e}")
            raise # Re-raise, don't return 0.0

    return total_sales


if __name__ == "__main__":
    try:
        quarterly_sales = calculate_quarterly_sales()
        print(f"Total sales for the first quarter: ${quarterly_sales:.2f}")
    except Exception as e:
        print(f"An error occurred: {e}") # Handle at the top level.
        logging.exception("Unhandled exception in main.")

