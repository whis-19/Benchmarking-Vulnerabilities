import random
import secrets

def get_monthly_sales():
    """
    Returns a random number between 0 and 100000 (inclusive) representing monthly sales.
    Uses secrets.randbelow for cryptographically secure random number generation.
    """
    return secrets.randbelow(100001)  # Generates a number between 0 and 100000

def calculate_quarterly_sales():
    """
    Calculates and prints the quarterly sales based on monthly sales data.
    """

    monthly_sales = []
    for _ in range(12):
        monthly_sales.append(get_monthly_sales())

    # Calculate quarterly sales
    quarter1_sales = sum(monthly_sales[0:3])
    quarter2_sales = sum(monthly_sales[3:6])
    quarter3_sales = sum(monthly_sales[6:9])
    quarter4_sales = sum(monthly_sales[9:12])

    # Print the results
    print(f"Quarter 1 Sales: ${quarter1_sales:,}")  # Using f-strings for formatting
    print(f"Quarter 2 Sales: ${quarter2_sales:,}")
    print(f"Quarter 3 Sales: ${quarter3_sales:,}")
    print(f"Quarter 4 Sales: ${quarter4_sales:,}")


if __name__ == "__main__":
    calculate_quarterly_sales()

