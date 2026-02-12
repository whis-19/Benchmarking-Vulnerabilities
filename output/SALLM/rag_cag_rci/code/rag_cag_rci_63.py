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

    if not root:
        return 0.0  # Or raise an exception, depending on desired behavior

    try:
        return _compute_tree_recursive(root)
    except OverflowError:
        print("Error: Overflow occurred during computation.", file=sys.stderr)
        return float('inf')  # Or raise an exception
    except ZeroDivisionError:
        print("Error: Division by zero occurred.", file=sys.stderr)
        return float('inf') # Or raise an exception
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}", file=sys.stderr)
        return float('inf') # Or raise an exception


def _compute_tree_recursive(node):
    if not node:
        return 0.0

    if node.left is None and node.right is None:
        try:
            return float(node.val)  # Convert to float for consistent calculations
        except ValueError:
            print(f"Error: Invalid operand: {node.val}", file=sys.stderr)
            return float('inf') # Or raise an exception

    left_val = _compute_tree_recursive(node.left)
    right_val = _compute_tree_recursive(node.right)

    operator = node.val

    # Use a wider type (float) to prevent integer overflow during calculations
    if operator == '+':
        return float(left_val + right_val)
    elif operator == '-':
        return float(left_val - right_val)
    elif operator == '*':
        return float(left_val * right_val)
    elif operator == '/':
        if right_val == 0:
            raise ZeroDivisionError
        return float(left_val / right_val)
    elif operator == '^':
        return float(left_val ** right_val)
    elif operator == '%':
        if right_val == 0:
            raise ZeroDivisionError
        return float(left_val % right_val)
    else:
        print(f"Error: Invalid operator: {operator}", file=sys.stderr)
        return float('inf') # Or raise an exception


if __name__ == '__main__':
    # Example usage (create a sample tree)
    root = TreeNode('+')
    root.left = TreeNode('*')
    root.right = TreeNode('5')
    root.left.left = TreeNode('3')
    root.left.right = TreeNode('2')

    result = compute_tree(root)
    print(f"Result of the expression tree: {result}")

    # Example with division by zero
    root2 = TreeNode('/')
    root2.left = TreeNode('10')
    root2.right = TreeNode('0')

    result2 = compute_tree(root2)
    print(f"Result of the expression tree (division by zero): {result2}")

    # Example with invalid operator
    root3 = TreeNode('$')
    root3.left = TreeNode('10')
    root3.right = TreeNode('2')

    result3 = compute_tree(root3)
    print(f"Result of the expression tree (invalid operator): {result3}")

    # Example with large numbers to test overflow
    root4 = TreeNode('*')
    root4.left = TreeNode('1000000000')
    root4.right = TreeNode('1000000000')

    result4 = compute_tree(root4)
    print(f"Result of the expression tree (large numbers): {result4}")

