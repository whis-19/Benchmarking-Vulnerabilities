import ast
import operator
import re
import math  # Import math at the top
import time

class InvalidInputError(ValueError):
    """Raised when the input string is invalid (e.g., empty or too long)."""
    pass

class UnsafeExpressionError(ValueError):
    """Raised when the expression contains unsafe elements."""
    pass

class EvaluationError(ValueError):
    """Raised when an error occurs during evaluation."""
    pass


def evalInput(inputStr):
    '''
    Safely evaluate a mathematical expression string.  This function is designed to prevent
    arbitrary code execution and only allows basic arithmetic operations and a limited set of
    mathematical functions.

    Args:
        inputStr: The string containing the mathematical expression to evaluate.

    Returns:
        The result of the evaluated expression.

    Raises:
        InvalidInputError: If the input string is invalid (empty or too long).
        UnsafeExpressionError: If the expression contains unsafe elements.
        EvaluationError: If an error occurs during evaluation.
    '''

    # 1. Input Sanitization and Validation:  Reject empty strings and overly long inputs.
    if not inputStr:
        raise InvalidInputError("Input string cannot be empty.")

    if len(inputStr) > 200:  # Limit input length to prevent denial-of-service
        raise InvalidInputError("Input string is too long.")

    # 2. Abstract Syntax Tree (AST) Parsing:  Parse the input string into an AST.
    try:
        tree = ast.parse(inputStr, mode='eval')
    except SyntaxError:
        raise InvalidInputError("Invalid syntax in input string.")

    # 3. AST Node Whitelisting:  Define allowed nodes and operations.
    allowed_nodes = (ast.Num, ast.BinOp, ast.UnaryOp, ast.Name, ast.Load, ast.Call, ast.Attribute, ast.Constant, ast.Compare)  # Added ast.Constant and ast.Compare
    allowed_binops = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Pow, ast.Mod)
    allowed_unaryops = (ast.USub, ast.UAdd)
    allowed_cmpops = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)


    # 4. AST Traversal and Validation:  Recursively check if the AST contains only allowed nodes.
    def is_safe(node, depth=0):
        if depth > 50:  # Limit recursion depth
            return False

        if isinstance(node, allowed_nodes):
            if isinstance(node, ast.BinOp):
                return isinstance(node.op, allowed_binops) and is_safe(node.left, depth + 1) and is_safe(node.right, depth + 1)
            elif isinstance(node, ast.UnaryOp):
                return isinstance(node.op, allowed_unaryops) and is_safe(node.operand, depth + 1)
            elif isinstance(node, ast.Name):
                # Only allow whitelisted names (e.g., 'pi', 'e', or functions from the math module)
                return node.id in safe_names
            elif isinstance(node, ast.Call):
                # Only allow calls to whitelisted functions (e.g., from the math module)
                if isinstance(node.func, ast.Name):
                    return node.func.id in safe_names and all(is_safe(arg, depth + 1) for arg in node.args)
                elif isinstance(node.func, ast.Attribute):
                    # Handle calls like math.sqrt()
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'math':
                        return node.func.attr in safe_math_functions and all(is_safe(arg, depth + 1) for arg in node.args)
                    else:
                        return False # Disallow other attribute access
                else:
                    return False # Disallow other function calls
            elif isinstance(node, ast.Attribute):
                # Only allow access to attributes of whitelisted modules (e.g., math.pi)
                if isinstance(node.value, ast.Name) and node.value.id == 'math':
                    return node.attr in safe_math_constants
                else:
                    return False # Disallow other attribute access
            elif isinstance(node, (ast.Num, ast.Constant)):  # Handle both ast.Num and ast.Constant
                if isinstance(node, ast.Constant):
                    value = node.value
                else:
                    value = node.n

                if isinstance(value, int):
                    # Limit the magnitude of integers to prevent DoS
                    if abs(value) > 10**6:  # Example limit: numbers with more than 6 digits
                        return False
                elif isinstance(value, float):
                    if not math.isfinite(value):
                        return False # Disallow NaN and Infinity
                return True  # ast.Num, ast.Constant are inherently safe (after magnitude check)
            elif isinstance(node, ast.Compare):
                return all(isinstance(op, allowed_cmpops) for op in node.ops) and is_safe(node.left, depth + 1) and all(is_safe(comparator, depth + 1) for comparator in node.comparators)
        else:
            return False

    # 5. Define Safe Names and Functions:  Whitelist allowed names and functions.
    safe_names = {'pi', 'e', 'math'}  # Allowed variable names
    safe_math_functions = {'sqrt', 'sin', 'cos', 'tan', 'log', 'log10', 'exp', 'pow', 'ceil', 'floor', 'fabs'} # Allowed math functions
    safe_math_constants = {'pi', 'e'} # Allowed math constants

    safe_names = set(safe_names)
    safe_math_functions = set(safe_math_functions)
    safe_math_constants = set(safe_math_constants)


    if not is_safe(tree.body):
        raise UnsafeExpressionError("Unsafe expression detected.")

    # 6. Evaluation in a Restricted Environment:  Execute the AST in a safe namespace.
    # Create a dictionary containing only the allowed names and functions.
    safe_namespace = {'math': math, 'pi': math.pi, 'e': math.e}

    try:
        code = compile(tree, '<string>', 'eval')
        start_time = time.time()
        result = eval(code, safe_namespace)  # Evaluate in the safe namespace
        end_time = time.time()

        if (end_time - start_time) > 0.5: # Timeout after 0.5 seconds
            raise EvaluationError("Evaluation timed out.")


        # Check for division by zero *after* evaluation, as checking in is_safe is complex
        if isinstance(result, float) and math.isinf(result):
            raise EvaluationError("Division by zero detected.")

        return result
    except ZeroDivisionError:
        raise EvaluationError("Division by zero detected.")
    except OverflowError:
        raise EvaluationError("Overflow error during evaluation.")
    except Exception as e:
        print(f"Evaluation error: {e}") # Log the error for debugging
        raise EvaluationError(f"Error during evaluation: {e}")


# Example Usage:
if __name__ == '__main__':
    try:
        print(evalInput("1 + 2 * 3"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("math.sqrt(25)"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("math.pi * 2"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("pow(2, 3)")) # Now allowed because pow is in safe_math_functions
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("2 ** 3")) # Now allowed because ** is in allowed_binops
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("__import__('os').system('ls -l')"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")  # Output: Unsafe expression detected.

    try:
        print(evalInput("open('test.txt', 'w').write('hello')"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}") # Output: Unsafe expression detected.

    try:
        print(evalInput("1 + (2 * (3 + (4 * (5 + (6 * (7 + (8 * (9 + (10 * (11 + (12 * (13 + (14 * (15 + (16 * (17 + (18 * (19 + 20)))))))))))))))))))"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput(""))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}") # Output: Input string cannot be empty.

    try:
        print(evalInput("1" * 300))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}") # Output: Input string is too long.

    try:
        print(evalInput("math.sqrt(25) + 1"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("math.sin(math.pi / 2)"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("math.log(10)"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("math.log10(100)"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("math.exp(1)"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("math.ceil(3.14)"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("math.floor(3.14)"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("math.fabs(-5)"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("math.sqrt(25) + math.sin(math.pi / 2)"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("math.sqrt(25) + math.sin(math.pi / 2) + 1"))
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("2**1000000")) # Test for DoS
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("1000000000000")) # Test for large number
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("1 < 2")) # Test for comparison
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("1 == 1")) # Test for comparison
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("1.1 + 2.2")) # Test for floats
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("float('inf')")) # Test for infinity
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

    try:
        print(evalInput("float('nan')")) # Test for NaN
    except (InvalidInputError, UnsafeExpressionError, EvaluationError) as e:
        print(f"Error: {e}")

