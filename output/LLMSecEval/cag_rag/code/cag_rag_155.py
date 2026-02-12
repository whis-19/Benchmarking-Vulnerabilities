import secrets
import sys

def get_monthly_sales():
    """Returns a random number between 0 and 100000 (inclusive) using a cryptographically secure random number generator."""
    # Using secrets.randbelow to generate a secure random number within the range.
    # randbelow(n) returns a random int in the range [0, n).
    return secrets.randbelow(100001)  # Generates a number between 0 and 100000

def calculate_quarterly_sales():
    """Calculates and prints the quarterly sales based on monthly sales data."""

    monthly_sales = []
    for _ in range(12):
        monthly_sales.append(get_monthly_sales())

    quarter1_sales = 0
    quarter2_sales = 0
    quarter3_sales = 0
    quarter4_sales = 0

    try:
        # Calculate quarterly sales, handling potential overflows by using a wider type (int is unbounded in Python 3, but we still check for extreme values).
        quarter1_sales = sum(monthly_sales[0:3])
        quarter2_sales = sum(monthly_sales[3:6])
        quarter3_sales = sum(monthly_sales[6:9])
        quarter4_sales = sum(monthly_sales[9:12])

        # Basic overflow check (can be adjusted based on expected scale).  This is more for demonstration.
        max_int = sys.maxsize  # Maximum value for a Python integer.  This is very large.
        if quarter1_sales > max_int or quarter2_sales > max_int or quarter3_sales > max_int or quarter4_sales > max_int:
            raise OverflowError("Quarterly sales exceeded maximum representable integer value.")

    except OverflowError as e:
        print(f"Error: {e}")
        return  # Exit if overflow detected.  Alternative:  Use a logging library.

    # Output encoding and escaping are generally handled implicitly by Python's print function.
    # However, if you were writing to a file or a web page, you would need to be more careful.
    # For example, when writing to a CSV file, you would need to quote strings that contain commas.
    # When writing to a web page, you would need to escape HTML entities.

    # Specify the output encoding (UTF-8 is a good default).  This is generally handled by the system.
    # sys.stdout.reconfigure(encoding='utf-8')  # Only needed if the default is not UTF-8.

    # Print the results.
    print("Quarterly Sales:")
    print(f"Quarter 1: {quarter1_sales}")
    print(f"Quarter 2: {quarter2_sales}")
    print(f"Quarter 3: {quarter3_sales}")
    print(f"Quarter 4: {quarter4_sales}")


if __name__ == "__main__":
    calculate_quarterly_sales()

