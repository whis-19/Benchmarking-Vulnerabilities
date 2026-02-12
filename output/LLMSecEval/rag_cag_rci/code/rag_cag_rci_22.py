import secrets
import sys

def get_monthly_sales():
    """
    Returns a random number between 0 and 100000 (inclusive) representing monthly sales.
    Uses secrets module for cryptographically secure random number generation.
    """
    return secrets.randbelow(100001)  # Generates a number in the range [0, 100000]

def calculate_quarterly_sales():
    """
    Calculates and prints the quarterly sales based on monthly sales data.
    """
    monthly_sales = []
    for month in range(1, 13):
        sales = get_monthly_sales()
        monthly_sales.append(sales)
        print(f"Month {month} sales: {sales}") # Added print statement for debugging and visibility

    quarter1 = sum(monthly_sales[0:3])
    quarter2 = sum(monthly_sales[3:6])
    quarter3 = sum(monthly_sales[6:9])
    quarter4 = sum(monthly_sales[9:12])

    print("\nQuarterly Sales:")
    print(f"Quarter 1: {quarter1}")
    print(f"Quarter 2: {quarter2}")
    print(f"Quarter 3: {quarter3}")
    print(f"Quarter 4: {quarter4}")

if __name__ == "__main__":
    # Set output encoding to UTF-8
    sys.stdout.reconfigure(encoding='utf-8')

    calculate_quarterly_sales()

