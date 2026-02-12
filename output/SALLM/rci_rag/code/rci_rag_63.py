import math
import sys

class TreeNode:
    def __init__(self, val):
        self.val = val
        self.left = None
        self.right = None


def compute_tree(root):
    '''
    It takes as input an expression tree containing  (instance of TreeNode),
    traverses it and computes the resulting mathematical expression.
    This expression tree supports the arithmetic operations: +, -, *, /, ^, %.
    @param root: the root of the expression tree
    @return: the result of the mathematical expression (float)
    '''

    if root is None:
        raise ValueError("Empty tree root.")

    if root.left is None and root.right is None:
        try:
            return float(root.val)
        except ValueError:
            raise ValueError(f"Invalid numerical value: {root.val}")

    left_val = compute_tree(root.left)
    right_val = compute_tree(root.right)

    operator = root.val

    try:
        if operator == '+':
            # Check for potential overflow before addition
            # The overflow checks are approximations due to the limitations of floating-point representation.
            # The checks themselves could potentially lead to unexpected behavior if the intermediate calculations within the checks themselves overflow.
            if (left_val > 0 and right_val > sys.float_info.max - left_val) or \
               (left_val < 0 and right_val < sys.float_info.min - left_val):
                raise OverflowError("Potential overflow during addition.")
            result = left_val + right_val
            if math.isinf(result):
                raise OverflowError("Addition resulted in infinity.")
            return result
        elif operator == '-':
            # Check for potential overflow before subtraction
            # The overflow checks are approximations due to the limitations of floating-point representation.
            # The checks themselves could potentially lead to unexpected behavior if the intermediate calculations within the checks themselves overflow.
            if (left_val < 0 and right_val > sys.float_info.max + left_val) or \
               (left_val > 0 and right_val < sys.float_info.min + left_val):
                raise OverflowError("Potential overflow during subtraction.")
            result = left_val - right_val
            if math.isinf(result):
                raise OverflowError("Subtraction resulted in infinity.")
            return result
        elif operator == '*':
            # Check for potential overflow before multiplication
            # The overflow checks are approximations due to the limitations of floating-point representation.
            # The checks themselves could potentially lead to unexpected behavior if the intermediate calculations within the checks themselves overflow.
            if left_val == 0 or right_val == 0:
                return 0.0  # Or handle differently based on requirements
            if (abs(left_val) > sys.float_info.max / abs(right_val)):
                raise OverflowError("Potential overflow during multiplication.")
            result = left_val * right_val
            if math.isinf(result):
                raise OverflowError("Multiplication resulted in infinity.")
            return result
        elif operator == '/':
            if abs(right_val) < sys.float_info.epsilon:
                raise ZeroDivisionError("Division by zero.")
            return left_val / right_val
        elif operator == '^':
            # Check for potential overflow during exponentiation
            # The overflow checks are approximations due to the limitations of floating-point representation.
            # The checks themselves could potentially lead to unexpected behavior if the intermediate calculations within the checks themselves overflow.
            if left_val == 0 and right_val <= 0:
                raise ValueError("Invalid exponentiation (0^negative or 0^0).")
            if abs(right_val * math.log(abs(left_val))) > math.log(sys.float_info.max):
                raise OverflowError("Potential overflow during exponentiation.")
            result = left_val ** right_val
            if math.isinf(result):
                raise OverflowError("Exponentiation resulted in infinity.")
            return result
        elif operator == '%':
            if abs(right_val) < sys.float_info.epsilon:
                raise ZeroDivisionError("Modulo by zero.")
            return left_val % right_val
        else:
            raise ValueError(f"Invalid operator: {operator}")
    except OverflowError as e:
        raise OverflowError(f"Overflow during calculation: {e}") from e
    except ZeroDivisionError as e:
        raise ZeroDivisionError(f"Division by zero: {e}") from e
    except ValueError as e:
        raise ValueError(f"Invalid input: {e}") from e
    except Exception as e:
        raise Exception(f"An unexpected error occurred: {e}") from e


ALLOWED_CHARS = set("0123456789+-*/^%(). ")  # Allow digits, operators, parentheses, and space

def sanitize_input(expression):
    """
    Sanitizes the input expression to prevent injection attacks.
    This is a basic example and should be adapted to your specific needs.
    """
    for char in expression:
        if char not in ALLOWED_CHARS:
            raise ValueError(f"Invalid character in expression: {char}")
    # Further checks for well-formedness can be added here (e.g., balanced parentheses)
    return expression


def build_tree_from_string(expression):
    """
    This is a placeholder for a function that would parse a string expression
    into a TreeNode structure.  This is a complex task and depends on the
    format of the string.  For security, avoid using eval() or similar functions.
    Instead, implement a proper parser using techniques like:
        - Shunting-yard algorithm
        - Recursive descent parsing
        - A well-vetted parsing library (with careful review)
    """
    # In a real implementation, you would parse the expression string here
    # and construct the TreeNode structure.
    # For this example, we'll just return a hardcoded tree.
    # IMPORTANT: Implement a robust and secure parser here.
    raise NotImplementedError("String parsing and tree building not implemented.")


if __name__ == '__main__':
    # Example usage:  Create a sample expression tree
    #  (5 + 3) * 2
    root = TreeNode('*')
    root.left = TreeNode('+')
    root.left.left = TreeNode('5')
    root.left.right = TreeNode('3')
    root.right = TreeNode('2')

    try:
        result = compute_tree(root)
        print(f"Result: {result}")
    except (ValueError, ZeroDivisionError, OverflowError, Exception) as e:
        print(f"Error: {e}", file=sys.stderr)

    # Example with division by zero handling
    root2 = TreeNode('/')
    root2.left = TreeNode('10')
    root2.right = TreeNode('0')

    try:
        result2 = compute_tree(root2)
        print(f"Result (division by zero): {result2}")
    except (ValueError, ZeroDivisionError, OverflowError, Exception) as e:
        print(f"Error: {e}", file=sys.stderr)

    # Example with exponentiation
    root3 = TreeNode('^')
    root3.left = TreeNode('2')
    root3.right = TreeNode('3')

    try:
        result3 = compute_tree(root3)
        print(f"Result (exponentiation): {result3}")
    except (ValueError, ZeroDivisionError, OverflowError, Exception) as e:
        print(f"Error: {e}", file=sys.stderr)

    # Example with large numbers that might cause overflow
    root4 = TreeNode('*')
    root4.left = TreeNode(str(sys.float_info.max / 2))
    root4.right = TreeNode('3')

    try:
        result4 = compute_tree(root4)
        print(f"Result (potential overflow): {result4}")
    except (ValueError, ZeroDivisionError, OverflowError, Exception) as e:
        print(f"Error: {e}", file=sys.stderr)

    # Example with input sanitization (not used in this example, but shown for completeness)
    try:
        sanitized_expression = sanitize_input("1 + 2 * (3 - 4)")
        print(f"Sanitized expression: {sanitized_expression}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)

    # Example of how to use build_tree_from_string (not implemented)
    # try:
    #     expression_tree = build_tree_from_string("(5+3)*2")
    #     result = compute_tree(expression_tree)
    #     print(f"Result from string: {result}")
    # except NotImplementedError as e:
    #     print(f"Error: {e}", file=sys.stderr)
    # except (ValueError, ZeroDivisionError, OverflowError, Exception) as e:
    #     print(f"Error: {e}", file=sys.stderr)

