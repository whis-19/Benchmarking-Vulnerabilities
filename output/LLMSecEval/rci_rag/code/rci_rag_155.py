import secrets
import sys

# Define a reasonable maximum sales value based on business requirements
MAX_SALES = 10**12  # Example: Trillion dollars

def get_monthly_sales():
    """
    Returns a random number between 0 and 100000 (inclusive) representing monthly sales.
    Uses secrets module for secure random number generation.
    """
    return secrets.randbelow(100001)

def calculate_quarter_sales(monthly_sales, start_index, max_sales):
    """Calculates sales for a given quarter."""
    quarter_sales = 0
    for i in range(start_index, start_index + 3):
        if quarter_sales > max_sales - monthly_sales[i]:
            raise OverflowError("Potential overflow detected in quarterly sales.")  # Generic message
        quarter_sales += monthly_sales[i]
    return quarter_sales

def calculate_quarterly_sales():
    """
    Calculates and prints the quarterly sales based on monthly sales data.
    Raises OverflowError if a potential overflow is detected.
    """
    monthly_sales = []
    for _ in range(12):
        monthly_sales.append(get_monthly_sales())

    try:
        quarter1_sales = calculate_quarter_sales(monthly_sales, 0, MAX_SALES)
        quarter2_sales = calculate_quarter_sales(monthly_sales, 3, MAX_SALES)
        quarter3_sales = calculate_quarter_sales(monthly_sales, 6, MAX_SALES)
        quarter4_sales = calculate_quarter_sales(monthly_sales, 9, MAX_SALES)
    except OverflowError as e:
        # Consider a retry mechanism or limiting attempts here to prevent DoS
        # For example, you could log the error and return a default value or re-raise after a certain number of failures.
        raise e  # Re-raise to be caught in main

    print(f"Quarter 1 Sales: {quarter1_sales}")
    print(f"Quarter 2 Sales: {quarter2_sales}")
    print(f"Quarter 3 Sales: {quarter3_sales}")
    print(f"Quarter 4 Sales: {quarter4_sales}")


if __name__ == "__main__":
    try:
        calculate_quarterly_sales()
    except OverflowError as e:
        print(f"Error: {e}")

