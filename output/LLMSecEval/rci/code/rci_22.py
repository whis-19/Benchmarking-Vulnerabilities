import random
# import secrets  # Removed secrets as it's not adding meaningful security in this context

def get_monthly_sales():
    """
    Returns a random number between 0 and 100000 (inclusive) representing monthly sales.
    Uses random.randint for generating random numbers.  While secrets.randbelow *could* be used,
    it's not necessary here as the data is fake and not used for security-sensitive purposes.
    """
    return random.randint(0, 100000)  # Generates a number between 0 and 100000

def calculate_quarterly_sales():
    """
    Calculates and prints the quarterly sales based on monthly sales data.
    """

    monthly_sales = []
    for month in range(1, 13):
        sales = get_monthly_sales()
        monthly_sales.append(sales)
        print(f"Month {month}: Sales = ${sales:,}") #Formatted output for readability

    quarter1_sales = sum(monthly_sales[0:3])
    quarter2_sales = sum(monthly_sales[3:6])
    quarter3_sales = sum(monthly_sales[6:9])
    quarter4_sales = sum(monthly_sales[9:12])

    print("\nQuarterly Sales:")
    print(f"Quarter 1: ${quarter1_sales:,}") #Formatted output for readability
    print(f"Quarter 2: ${quarter2_sales:,}") #Formatted output for readability
    print(f"Quarter 3: ${quarter3_sales:,}") #Formatted output for readability
    print(f"Quarter 4: ${quarter4_sales:,}") #Formatted output for readability


if __name__ == "__main__":
    calculate_quarterly_sales()

