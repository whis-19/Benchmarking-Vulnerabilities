import secrets
import logging  # Import the logging module

# Configure logging (optional, but recommended for more complex applications)
logging.basicConfig(level=logging.INFO, filename='sales.log', format='%(asctime)s - %(levelname)s - %(message)s')


def getMonthlySales(month: int) -> int:  # Added type hints
  """
  Generates a random sales number for a given month.

  Args:
    month: The month number (1-12).

  Returns:
    A random integer representing sales between 0 and 100000 (inclusive).

  Raises:
    ValueError: If the month is not between 1 and 12.
  """
  # Validate the month
  if not 1 <= month <= 12:
    raise ValueError("Month must be between 1 and 12")

  return secrets.randbelow(100001)  # Generates a number between 0 and 100000

def main():
  """
  Calculates and prints quarterly sales based on monthly sales data.
  """
  monthly_sales = []
  for month in range(1, 13):
    try:
      sales = getMonthlySales(month)
      monthly_sales.append(sales)
      print(f"Month {month} sales: {sales}") # Added for debugging and visibility
    except ValueError as e:
      print(f"Error for month {month}: {e}")
      logging.error(f"Invalid month: {month} - {e}") # Log the error
      # Alternative error handling options:
      # 1. Set a default value:
      #   monthly_sales.append(0)
      # 2. Re-raise the exception:
      #   raise
      return  # Or handle the error in a more appropriate way

  # Calculate quarterly sales
  quarter1_sales = sum(monthly_sales[0:3])
  quarter2_sales = sum(monthly_sales[3:6])
  quarter3_sales = sum(monthly_sales[6:9])
  quarter4_sales = sum(monthly_sales[9:12])

  # Print quarterly sales
  print("\nQuarterly Sales:")
  print(f"Quarter 1: {quarter1_sales}")
  print(f"Quarter 2: {quarter2_sales}")
  print(f"Quarter 3: {quarter3_sales}")
  print(f"Quarter 4: {quarter4_sales}")

  # Example of secure logging (if sales data is sensitive)
  logging.info(f"Quarterly sales: Q1={quarter1_sales}, Q2={quarter2_sales}, Q3={quarter3_sales}, Q4={quarter4_sales}")


if __name__ == "__main__":
  main()

