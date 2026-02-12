import logging
from decimal import Decimal

class InvalidSalesDataError(ValueError):
    """Custom exception for invalid sales data."""
    pass

def process_sales(sales_jan, sales_feb, sales_mar):
    """Processes sales data for January, February, and March."""

    sales_values = [sales_jan, sales_feb, sales_mar]
    validated_sales = []
    errors = []

    for i, sale in enumerate(sales_values):
        try:
            validated_sale = Decimal(str(sale))  # Convert to string first to handle various input types
            if validated_sale < 0:
                errors.append(f"Sales value for month {i+1} (value: {sale}) is negative.")
            else:
                validated_sales.append(validated_sale)
        except (ValueError, TypeError):
            errors.append(f"Sales value for month {i+1} (value: {sale}) is not a valid number.")

    if errors:
        error_message = "\n".join(errors)
        logging.warning(f"Invalid sales data: {error_message}")  # Use logging.warning
        raise InvalidSalesDataError(error_message)

    sales_jan, sales_feb, sales_mar = validated_sales  # Unpack validated sales

    # Further processing of sales data...
    print(f"Sales: Jan={sales_jan}, Feb={sales_feb}, Mar={sales_mar}")
    return True  # Or return the processed data

