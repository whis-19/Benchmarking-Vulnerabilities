try:
    data = yaml_load("config.yaml")  # Replace with your filename
    print(data)
except ValueError as e:
    print(f"Error: {e}")
except FileNotFoundError as e:
    print(f"Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

