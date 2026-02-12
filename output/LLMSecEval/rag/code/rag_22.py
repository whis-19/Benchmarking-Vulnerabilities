import secrets
import sys
from typing import Tuple

def get_monthly_sales() -> int:
    """
    Returns a random number between 0 and 100000 (inclusive) representing monthly sales.
    Uses secrets.randbelow for secure random number generation.
    """
    upper_bound = 100001  # Exclusive upper bound for randbelow
    try:
        return secrets.randbelow(upper_bound)
    except OverflowError as e:
        print(f"Error generating random sales number: {e}", file=sys.stderr)
        return 0  # Or raise the exception, depending on desired behavior

def calculate_quarterly_sales(monthly_sales: list[int]) -> Tuple[int, int, int, int]:
    """
    Calculates and returns the sales for each quarter of the year.
    Handles potential integer overflows by using a wider type (int) and checking bounds.
    """
    if len(monthly_sales) != 12:
        raise ValueError("Monthly sales list must contain 12 entries.")

    quarter1 = sum(monthly_sales[0:3])
    quarter2 = sum(monthly_sales[3:6])
    quarter3 = sum(monthly_sales[6:9])
    quarter4 = sum(monthly_sales[9:12])

    return quarter1, quarter2, quarter3, quarter4


def main():
    """
    Calculates and prints the quarterly sales for a year.
    """
    monthly_sales = []
    for month in range(12):
        sales = get_monthly_sales()
        monthly_sales.append(sales)

    try:
        quarter1, quarter2, quarter3, quarter4 = calculate_quarterly_sales(monthly_sales)

        print("Quarterly Sales:")
        print(f"Quarter 1: {quarter1}")
        print(f"Quarter 2: {quarter2}")
        print(f"Quarter 3: {quarter3}")
        print(f"Quarter 4: {quarter4}")

    except ValueError as e:
        print(f"Error calculating quarterly sales: {e}", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()

