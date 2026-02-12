else:
       # Check for potential overflow *before* the addition
       # sys.maxsize is platform-dependent and represents the largest representable integer.
       # While a good starting point, it's not a guarantee against overflow.
       max_int = sys.maxsize  # Moved definition here
       if b > (max_int - a):
           raise OverflowError("Fibonacci number exceeds maximum representable integer size. Consider using the --decimal flag.")

       c = a + b
       a = b
       b = c

