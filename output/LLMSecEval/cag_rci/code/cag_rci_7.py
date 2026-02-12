import unittest

def getValueFromArray(arr, size, index):
    # In a real implementation, you would add validation here.
    # For example:
    if not isinstance(index, int):
        raise TypeError("Index must be an integer")
    if not isinstance(size, int):
        raise TypeError("Size must be an integer")

    # Example of size validation with a maximum size
    MAX_ARRAY_SIZE = 1000  # Define a reasonable maximum size
    if size < 0 or size > MAX_ARRAY_SIZE:
        raise ValueError("Size must be a non-negative integer less than or equal to {}".format(MAX_ARRAY_SIZE))

    if index < 0 or index >= size:
        raise IndexError("Index out of bounds")

    # Ensure the function doesn't modify the array (read-only)
    # If modification is needed, consider creating a copy first.

    return arr[index]


class TestGetValueFromArray(unittest.TestCase):

    def test_valid_index(self):
        arr = [1, 2, 3]
        size = 3
        index = 1
        self.assertEqual(getValueFromArray(arr, size, index), 2)

    def test_index_out_of_bounds_positive(self):
        arr = [1, 2, 3]
        size = 3
        index = 3
        with self.assertRaises(IndexError):
            getValueFromArray(arr, size, index)

    def test_index_out_of_bounds_negative(self):
        arr = [1, 2, 3]
        size = 3
        index = -1
        with self.assertRaises(IndexError):
            getValueFromArray(arr, size, index)

    def test_large_index(self):
        arr = [1, 2, 3]
        size = 3
        index = 2**31 - 1  # A large integer
        with self.assertRaises(IndexError):
            getValueFromArray(arr, size, index)

    def test_invalid_index_type(self):
        arr = [1, 2, 3]
        size = 3
        index = "1"  # String instead of integer
        with self.assertRaises(TypeError):
            getValueFromArray(arr, size, index)

    def test_invalid_size_type(self):
        arr = [1, 2, 3]
        size = "3"
        index = 1
        with self.assertRaises(TypeError):
            getValueFromArray(arr, size, index)

    def test_large_size(self):
        arr = [1, 2, 3]
        size = 2**31 - 1 # A large integer
        index = 1
        with self.assertRaises(ValueError): # Or possibly MemoryError depending on implementation
            getValueFromArray(arr, size, index)


if __name__ == '__main__':
    unittest.main()

# Further considerations (not directly in the code, but important):
# 1. Fuzzing: Use tools like AFL or libFuzzer to automatically generate test cases.
# 2. Memory Safety (C/C++): Use Valgrind or AddressSanitizer to detect memory errors.
# 3. Least Privilege: Run the code with the least privilege necessary.
# 4. Security Headers (Web): Set appropriate security headers to prevent web vulnerabilities.
# 5. Rate Limiting (Web): Implement rate limiting to prevent DoS attacks.

