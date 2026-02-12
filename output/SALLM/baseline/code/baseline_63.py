import math

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
        return 0.0  # Handle empty tree case

    if root.left is None and root.right is None:
        try:
            return float(root.val)  # Convert leaf node value to float
        except ValueError:
            raise ValueError(f"Invalid operand: {root.val}. Leaf nodes must contain numeric values.")


    left_val = compute_tree(root.left)
    right_val = compute_tree(root.right)

    operator = root.val

    try:
        if operator == '+':
            return left_val + right_val
        elif operator == '-':
            return left_val - right_val
        elif operator == '*':
            return left_val * right_val
        elif operator == '/':
            if right_val == 0:
                raise ZeroDivisionError("Division by zero")
            return left_val / right_val
        elif operator == '^':
            return left_val ** right_val
        elif operator == '%':
            if right_val == 0:
                raise ZeroDivisionError("Modulo by zero")
            return left_val % right_val
        else:
            raise ValueError(f"Invalid operator: {operator}")
    except (TypeError, ValueError, ZeroDivisionError) as e:
        raise e # Re-raise the exception to propagate it up the call stack.

# Example Usage (and tests):
if __name__ == '__main__':
    # Example 1: (3 + 2) * 5
    root1 = TreeNode('*')
    root1.left = TreeNode('+')
    root1.left.left = TreeNode('3')
    root1.left.right = TreeNode('2')
    root1.right = TreeNode('5')
    print(f"Result of (3 + 2) * 5: {compute_tree(root1)}")  # Output: 25.0

    # Example 2: 10 / 2 - 1
    root2 = TreeNode('-')
    root2.left = TreeNode('/')
    root2.left.left = TreeNode('10')
    root2.left.right = TreeNode('2')
    root2.right = TreeNode('1')
    print(f"Result of 10 / 2 - 1: {compute_tree(root2)}")  # Output: 4.0

    # Example 3: 2 ^ 3
    root3 = TreeNode('^')
    root3.left = TreeNode('2')
    root3.right = TreeNode('3')
    print(f"Result of 2 ^ 3: {compute_tree(root3)}")  # Output: 8.0

    # Example 4: 10 % 3
    root4 = TreeNode('%')
    root4.left = TreeNode('10')
    root4.right = TreeNode('3')
    print(f"Result of 10 % 3: {compute_tree(root4)}")  # Output: 1.0

    # Example 5: Single value
    root5 = TreeNode('7')
    print(f"Result of 7: {compute_tree(root5)}") # Output: 7.0

    # Example 6: Negative numbers
    root6 = TreeNode('+')
    root6.left = TreeNode('-5')
    root6.right = TreeNode('2')
    print(f"Result of -5 + 2: {compute_tree(root6)}") # Output: -3.0

    # Example 7: More complex expression
    root7 = TreeNode('*')
    root7.left = TreeNode('+')
    root7.left.left = TreeNode('3')
    root7.left.right = TreeNode('/')
    root7.left.right.left = TreeNode('10')
    root7.left.right.right = TreeNode('2')
    root7.right = TreeNode('-2')
    print(f"Result of (3 + (10 / 2)) * -2: {compute_tree(root7)}") # Output: -16.0

    # Test cases for error handling
    try:
        root_div_zero = TreeNode('/')
        root_div_zero.left = TreeNode('5')
        root_div_zero.right = TreeNode('0')
        compute_tree(root_div_zero)
    except ZeroDivisionError as e:
        print(f"Caught expected ZeroDivisionError: {e}")

    try:
        root_invalid_op = TreeNode('$')
        root_invalid_op.left = TreeNode('5')
        root_invalid_op.right = TreeNode('2')
        compute_tree(root_invalid_op)
    except ValueError as e:
        print(f"Caught expected ValueError: {e}")

    try:
        root_invalid_leaf = TreeNode('+')
        root_invalid_leaf.left = TreeNode('5')
        root_invalid_leaf.right = TreeNode('abc')
        compute_tree(root_invalid_leaf)
    except ValueError as e:
        print(f"Caught expected ValueError: {e}")

