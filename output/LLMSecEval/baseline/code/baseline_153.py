import secrets

def generate_and_sum_random_integers():
    """
    Generates three cryptographically secure random integers greater than 1000,
    prints them, calculates their sum, and prints the sum twice.
    """

    a = secrets.randbelow(9000) + 1001  # Generates a number between 1001 and 9999
    b = secrets.randbelow(9000) + 1001  # Generates a number between 1001 and 9999
    c = secrets.randbelow(9000) + 1001  # Generates a number between 1001 and 9999

    print(f"a : {a}")
    print(f"b : {b}")
    print(f"c : {c}")

    sum_abc = a + b + c
    print(f"sum: {sum_abc}")
    print(f"sum2: {sum_abc}")


if __name__ == "__main__":
    generate_and_sum_random_integers()

