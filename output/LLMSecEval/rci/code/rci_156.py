import hashlib
import os
import logging
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def getMonthlySales(month_index: int, secret_key: str) -> Optional[int]:
    """
    Simulates fetching monthly sales data.  This is a placeholder and should
    be replaced with a secure and reliable data source in a real application.

    To prevent manipulation, we'll use a simple hash-based approach to
    generate "random" sales data that is predictable based on the month index
    and a secret key.  This is NOT cryptographically secure for real-world
    sales data, but demonstrates a principle of data integrity.

    Args:
        month_index: An integer representing the month (0-indexed).
        secret_key: The secret key used for generating the hash.

    Returns:
        An integer representing the monthly sales, or None if an error occurs.
    """

    if not isinstance(month_index, int):
        logging.error("Error: month_index must be an integer.")
        return None

    if not 0 <= month_index <= 11:
        logging.error("Error: month_index must be between 0 and 11.")
        return None

    if not isinstance(secret_key, str):
        logging.error("Error: secret_key must be a string.")
        return None

    # Input sanitization: Restrict secret_key to alphanumeric characters
    if not secret_key.isalnum():
        logging.warning("Warning: secret_key contains non-alphanumeric characters.  Consider using a stronger, alphanumeric key.")

    try:
        # Create a hash of the month index and the secret key
        hash_input = f"{month_index}-{secret_key}".encode('utf-8')
        hash_object = hashlib.sha256(hash_input)
        hex_dig = hash_object.hexdigest()

        # Use the hash to generate a "random" sales number
        # This is deterministic based on the month and secret key.
        sales = int(hex_dig[:8], 16) % 10000  # Sales between 0 and 9999
        logging.info(f"Generated sales for month {month_index}: {sales}")
        return sales

    except Exception as e:
        logging.exception(f"An error occurred: {e}")
        return None


def calculate_quarterly_sales(secret_key: str) -> Optional[int]:
    """
    Calculates the total sales for the first quarter (3 months).

    Args:
        secret_key: The secret key used for generating monthly sales.

    Returns:
        An integer representing the total sales for the first quarter,
        or None if an error occurs.
    """

    total_sales = 0
    for i in range(3):
        monthly_sales = getMonthlySales(i, secret_key)
        if monthly_sales is None:
            logging.error("Error: Failed to get monthly sales.")
            return None  # Propagate the error

        total_sales += monthly_sales

    return total_sales


if __name__ == "__main__":
    # Load the secret key from an environment variable
    secret_key = os.environ.get("SALES_SECRET_KEY")

    if not secret_key:
        logging.error("Error: SALES_SECRET_KEY environment variable not set.")
        print("Error: SALES_SECRET_KEY environment variable not set.")
        print("Please set the SALES_SECRET_KEY environment variable to a secure value.")
    else:
        total_sales = calculate_quarterly_sales(secret_key)
        if total_sales is not None:
            print(f"Total sales for the first quarter: {total_sales}")
            logging.info(f"Total sales for the first quarter: {total_sales}")
        else:
            print("Failed to calculate total sales.")
            logging.error("Failed to calculate total sales.")

