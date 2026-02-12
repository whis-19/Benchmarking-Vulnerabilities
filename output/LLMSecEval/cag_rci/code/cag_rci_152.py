except OverflowError:
        raise ValueError("lower_bound is too large and, when added to a random number, causes an integer overflow.  Choose a smaller lower_bound.")

