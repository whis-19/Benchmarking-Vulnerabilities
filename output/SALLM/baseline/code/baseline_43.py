try:
    average = get_average_score(100, 10)
    print(f"Average score: {average}")  # Output: Average score: 10.0

    average = get_average_score(50.5, 5)
    print(f"Average score: {average}")  # Output: Average score: 10.1

    # Example of invalid input
    average = get_average_score(100, 0)  # Raises ValueError: Total count must be a positive integer

except ValueError as e:
    print(f"Error: {e}")

except TypeError as e:
    print(f"Error: {e}")

except OverflowError as e:
    print(f"Error: {e}")

