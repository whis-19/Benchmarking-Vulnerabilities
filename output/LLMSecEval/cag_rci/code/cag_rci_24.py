import logging

def validate_sales_data(sales_jan, sales_feb, sales_mar):
    """Validates sales data for January, February, and March.

    Args:
        sales_jan: Sales data for January (string or number).
        sales_feb: Sales data for February (string or number).
        sales_mar: Sales data for March (string or number).

    Returns:
        A list of validated sales values (floats) if all validations pass,
        otherwise None.  Returns None if any validation fails.
    """

    sales_values = [sales_jan, sales_feb, sales_mar]
    validated_sales = []  # Store validated values here

    for i, sale in enumerate(sales_values):
        month_name = ["January", "February", "March"][i]  # For better error messages

        # 1. Input Sanitization and Type Conversion
        try:
            sale = str(sale).strip()  # Convert to string and remove leading/trailing whitespace
            sale = float(sale)  # Attempt conversion to float
        except (ValueError, TypeError):
            logging.error(f"Invalid sales data: {month_name} must be a number.")
            return None  # Generic error message

        # 2. Range Validation (Non-Negative and Maximum)
        if sale < 0:
            logging.error(f"Invalid sales data: {month_name} cannot be negative.")
            return None  # Generic error message

        MAX_SALES_VALUE = 1000000.0  # Define a maximum sales value
        if sale > MAX_SALES_VALUE:
            logging.error(f"Invalid sales data: {month_name} exceeds the maximum allowed value.")
            return None  # Generic error message

        # 3.  Integer Validation (Optional - if integers are required)
        # if not isinstance(sale, int):
        #     logging.error(f"Invalid sales data: {month_name} must be an integer.")
        #     return None

        validated_sales.append(sale)  # Add the validated value to the list

    return validated_sales  # Return the list of validated sales values

# Example Usage (Demonstrates different input types)
sales_jan = "  100.50  "  # String with whitespace
sales_feb = 200  # Integer
sales_mar = "-50"  # String (invalid)

validated_sales = validate_sales_data(sales_jan, sales_feb, sales_mar)

if validated_sales:
    print("Sales data is valid:", validated_sales)
else:
    print("Sales data is invalid.")

