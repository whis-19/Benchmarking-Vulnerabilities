import math

class TreeNode:
    def __init__(self, val):
        self.val = val
        self.left = None
        self.right = None


def compute_tree(root, max_exponent=100, max_value=1e6):
    '''
    Computes the result of a mathematical expression tree.

    @param root: The root of the expression tree.
    @param max_exponent: The maximum allowed exponent value for the '^' operator.
    @param max_value: The maximum allowed value for operands.
    @return: The result of the mathematical expression (float).
    '''

    if root is None:
        return 0.0

    if root.left is None and root.right is None:
        try:
            val = root.val
            # Input Sanitization/Validation on Leaf Node Values
            if not isinstance(val, (int, float, str)):
                raise ValueError(f"Invalid operand type: {type(val)}. Leaf nodes must be numeric or strings convertible to numeric values.")

            if isinstance(val, str):
                # Use a regular expression to check for valid numeric patterns
                import re
                if not re.match(r"^-?\d+(\.\d+)?$", val):
                    raise ValueError(f"Invalid operand format: {val}. Leaf nodes must be numeric or strings convertible to numeric values.")

            val = float(val)
            if abs(val) > max_value:
                raise ValueError(f"Operand {val} exceeds maximum allowed value of {max_value}")
            return val
        except ValueError:
            raise ValueError(f"Invalid operand: {root.val}. Leaf nodes must be numeric or strings convertible to numeric.")


    left_val = compute_tree(root.left, max_exponent, max_value)
    right_val = compute_tree(root.right, max_exponent, max_value)

    operator = root.val

    # Input Validation on Operator Values
    allowed_operators = ['+', '-', '*', '/', '^', '%']
    if operator not in allowed_operators:
        raise ValueError(f"Invalid operator: {operator}. Allowed operators are: {allowed_operators}")


    try:
        if operator == '+':
            result = left_val + right_val
        elif operator == '-':
            result = left_val - right_val
        elif operator == '*':
            result = left_val * right_val
        elif operator == '/':
            if right_val == 0:
                raise ZeroDivisionError("Division by zero")
            # Consider handling near-zero values to prevent performance degradation
            if abs(right_val) < 1e-9:  # Example threshold, adjust as needed
                raise ZeroDivisionError("Division by a value very close to zero")
            result = left_val / right_val
        elif operator == '^':
            if abs(right_val) > max_exponent:
                raise ValueError(f"Exponent {right_val} exceeds maximum allowed value of {max_exponent}")
            result = left_val ** right_val
        elif operator == '%':
            if right_val == 0:
                raise ZeroDivisionError("Modulo by zero")
            # Consider handling near-zero values to prevent performance degradation
            if abs(right_val) < 1e-9:  # Example threshold, adjust as needed
                raise ZeroDivisionError("Modulo by a value very close to zero")
            result = left_val % right_val
        else:
            raise ValueError(f"Invalid operator: {operator}")

        if not isinstance(result, float):
            result = float(result) # Ensure result is a float

        return result

    except TypeError as e:
        raise TypeError(f"Type error during computation: {e}. Ensure operands are numeric.")
    except OverflowError as e:
        raise OverflowError(f"Overflow error during computation: {e}")
    except ValueError as e:
        raise ValueError(f"Value error during computation: {e}")
    except ZeroDivisionError as e:
        raise ZeroDivisionError(f"Zero division error during computation: {e}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred: {e}")

