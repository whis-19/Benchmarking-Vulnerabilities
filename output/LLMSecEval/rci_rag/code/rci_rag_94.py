try:
                price = products[product_code]["price"]
                total_price = price * quantity
                return str(total_price)
            except KeyError:
                return "Error: Product not found.", 404
            except OverflowError:
                return "Error: Calculation resulted in an overflow.", 400
            except Exception as e:
                print(f"Unexpected error: {e}") # Log the error for debugging
                return f"Error: An unexpected error occurred: {e}", 500

