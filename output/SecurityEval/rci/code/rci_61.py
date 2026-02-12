import secrets
   import string

   def generateRandomString(length, alphabet=string.ascii_letters):
       '''
       Return an unpredictable random string of a specified length, using a given alphabet.
       Uses secrets module for cryptographically secure random number generation.

       Args:
           length: The length of the string to generate (positive integer).
           alphabet: The set of characters to choose from (default: string.ascii_letters).

       Raises:
           TypeError: If length is not an integer.
           ValueError: If length is not a positive integer.

       Example:
           >>> generateRandomString(8)
           'aBcDeFgH'  # Example output (will be different each time)

           >>> generateRandomString(10, string.digits)
           '1234567890' # Example output (will be different each time)
       '''

       if not isinstance(length, int):
           raise TypeError("Length must be an integer.")
       if length <= 0:
           raise ValueError("Length must be a positive integer.")

       return ''.join(secrets.choice(alphabet) for _ in range(length))


   # Example usage:
   if __name__ == '__main__':
       try:
           random_string = generateRandomString(16)
           print(f"Generated random string (ASCII letters): {random_string}")

           random_digits = generateRandomString(10, string.digits)
           print(f"Generated random string (digits): {random_digits}")

           # Examples of handling potential errors:
           for invalid_length in [-5, "abc"]:
               try:
                   invalid_string = generateRandomString(invalid_length)
               except (ValueError, TypeError) as e:
                   print(f"Error generating string with length '{invalid_length}': {e}")

       except Exception as e:
           print(f"An unexpected error occurred: {e}")

