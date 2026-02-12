import secrets
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def getMonthlySales(month):
  """
  Generates a secure random sales number for a given month.

  Args:
    month: The month number (1-12).

  Returns:
    A secure random integer representing sales between 0 and 100000 (inclusive).

  Raises:
    ValueError: If the month is not within the valid range (1-12).
  """
  if not 1 <= month <= 12:
    raise ValueError("Month must be between 1 and 12")

  return secrets.randbelow(100001)


def calculate_quarterly_sales():
  """
  Calculates and prints the quarterly sales based on monthly sales.
  """
  monthly_sales = []
  # Example of a very basic authentication placeholder (replace with a real implementation)
  # In a real application, you'd use a library like Flask-Login or Django's authentication system
  is_authorized = True  # Replace with actual authentication check

  if not is_authorized:
      logging.warning("Unauthorized access attempt to calculate_quarterly_sales")
      print("Unauthorized")
      return

  for month in range(1, 13):
    try:
      sales = getMonthlySales(month)
      monthly_sales.append(sales)
      # Consider removing the print statement in production
      print(f"Month {month} sales: {sales}")
      # Log sales, but consider redacting or using DEBUG level in production
      logging.info(f"Month {month} sales: {sales}")
    except ValueError as e:
      logging.error(f"Error generating sales for month {month}: {e}")
      # Handle the error appropriately (e.g., set sales to 0, retry, etc.)
      monthly_sales.append(0)  # Example: Set sales to 0 on error
    except Exception as e:
      logging.exception(f"Unexpected error generating sales for month {month}: {e}")
      # Handle unexpected errors (e.g., exit the program, notify admin)
      # Example:  Retry the operation a few times before giving up
      #           Or, send an email notification to an administrator
      return  # Example: Exit if a critical error occurs

  quarter1_sales = sum(monthly_sales[0:3])
  quarter2_sales = sum(monthly_sales[3:6])
  quarter3_sales = sum(monthly_sales[6:9])
  quarter4_sales = sum(monthly_sales[9:12])

  print("\nQuarterly Sales:")
  print(f"Quarter 1: {quarter1_sales}")
  print(f"Quarter 2: {quarter2_sales}")
  print(f"Quarter 3: {quarter3_sales}")
  print(f"Quarter 4: {quarter4_sales}")


if __name__ == "__main__":
  calculate_quarterly_sales()

