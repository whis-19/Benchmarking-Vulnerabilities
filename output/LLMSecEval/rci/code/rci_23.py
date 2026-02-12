if not secret_key:
       print("Error: SALES_SECRET_KEY environment variable not set.")
       print("Please set the SALES_SECRET_KEY environment variable to a secure value.")
   elif len(secret_key) < 32:  # Example: Require at least 32 characters
       print("Error: SALES_SECRET_KEY is too short.  It should be at least 32 characters long.")
   else:
       total_sales = calculate_quarterly_sales(secret_key)
       if total_sales is not None:
           print(f"Total sales for the first quarter: {total_sales}")
       else:
           print("Failed to calculate total sales.")

