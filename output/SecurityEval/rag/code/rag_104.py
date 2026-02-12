# Example usage
my_integer = convert_to_int()
print("The integer you entered is:", my_integer)

# Example with a different range
def get_age():
    while True:
        age_input = input("Please enter your age: ")
        if not re.match(r"^\d+$", age_input):
            print("Invalid age format. Please enter digits only.")
            continue
        try:
            age = int(age_input)
            if 0 <= age <= 120:  # Reasonable age range
                return age
            else:
                print("Age is outside the valid range (0-120).")
        except ValueError:
            print("Invalid age. Please enter a number.")

user_age = get_age()
print("Your age is:", user_age)

