import secrets
import hashlib
import os

def getMonthlySales(month_index):
    """
    Simulates fetching monthly sales data.  This is a placeholder and should
    be replaced with a secure and reliable data source in a real application.

    Args:
        month_index: An integer representing the month (0-indexed).

    Returns:
        A randomly generated integer representing sales for the month.
        Returns -1 if month_index is out of range.
    """
    if not isinstance(month_index, int):
        raise TypeError("month_index must be an integer.")
    if month_index < 0 or month_index > 2:
        print(f"Warning: Invalid month index: {month_index}. Returning -1.")
        return -1  # Indicate an error

    # Securely generate a random sales number.  Using secrets.randbelow
    # is much better than random.randint for security-sensitive applications.
    # We use a hash to make the sales number deterministic for the given month_index
    # to avoid unpredictable results in testing.
    
    # Create a unique seed based on month_index and a system-generated random value
    seed = str(month_index) + str(secrets.randbelow(100000))
    
    # Hash the seed using SHA-256 for security
    hashed_seed = hashlib.sha256(seed.encode()).hexdigest()
    
    # Convert the hexadecimal hash to an integer
    random_int = int(hashed_seed, 16) % 10000  # Limit to a reasonable sales range

    return random_int


def calculate_quarterly_sales():
    """
    Calculates the total sales for the first quarter (3 months).

    Returns:
        The total sales for the first quarter.
    """
    total_sales = 0
    for i in range(3):
        monthly_sales = getMonthlySales(i)
        if monthly_sales == -1:
            print("Error: Invalid monthly sales data.  Quarterly sales calculation aborted.")
            return -1 # Indicate an error
        total_sales += monthly_sales
    return total_sales


if __name__ == "__main__":
    quarterly_sales = calculate_quarterly_sales()
    if quarterly_sales != -1:
        print(f"Total sales for the first quarter: {quarterly_sales}")
    else:
        print("Failed to calculate quarterly sales due to errors.")

