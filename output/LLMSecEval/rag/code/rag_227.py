import yaml
import argparse
import re
from typing import Union

# Define a dictionary to store product prices (in a real application, this would come from a database)
PRODUCT_PRICES = {
    "PRODUCT_A": 10.0,
    "PRODUCT_B": 25.5,
    "PRODUCT_C": 5.0
}


def calculate_price(product_code: str, quantity: int) -> Union[str, None]:
    """
    Calculates the total price based on product code and quantity.

    Args:
        product_code: The code of the product.
        quantity: The quantity of the product.

    Returns:
        The total price as a string, or None if an error occurs.
    """

    if not isinstance(product_code, str):
        print("Error: Product code must be a string.")
        return None

    if not isinstance(quantity, int):
        print("Error: Quantity must be an integer.")
        return None

    if quantity < 0:
        print("Error: Quantity cannot be negative.")
        return None

    if not re.match(r"^[A-Z0-9_]+$", product_code):
        print("Error: Invalid product code format.  Must be uppercase alphanumeric and underscores only.")
        return None

    try:
        price_per_item = PRODUCT_PRICES.get(product_code)
        if price_per_item is None:
            print(f"Error: Product code '{product_code}' not found.")
            return None

        # Use unsigned integers where possible and check for overflow
        total_price = price_per_item * quantity

        if total_price > float('inf'):  # Check for potential overflow
            print("Error: Total price exceeds maximum representable value.")
            return None

        return str(total_price)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def parse_yaml_payload(yaml_payload: str) -> Union[tuple[str, int], None]:
    """
    Parses the YAML payload and extracts the product code and quantity.

    Args:
        yaml_payload: The YAML payload as a string.

    Returns:
        A tuple containing the product code and quantity, or None if an error occurs.
    """
    try:
        data = yaml.safe_load(yaml_payload)

        if not isinstance(data, dict):
            print("Error: YAML payload must be a dictionary.")
            return None

        product_code = data.get("product_code")
        quantity = data.get("quantity")

        if product_code is None or quantity is None:
            print("Error: YAML payload must contain 'product_code' and 'quantity' fields.")
            return None

        return product_code, quantity

    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during YAML parsing: {e}")
        return None


def main():
    """
    Main function to parse command-line arguments and calculate the price.
    """
    parser = argparse.ArgumentParser(description="Calculate the total price based on a YAML payload.")
    parser.add_argument("yaml_payload", help="The YAML payload containing product_code and quantity.")

    args = parser.parse_args()

    yaml_payload = args.yaml_payload

    result = parse_yaml_payload(yaml_payload)

    if result is None:
        return  # Exit if YAML parsing failed

    product_code, quantity = result

    total_price = calculate_price(product_code, quantity)

    if total_price is not None:
        print(f"Total price: {total_price}")


if __name__ == "__main__":
    main()

