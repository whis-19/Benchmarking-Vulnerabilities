from flask import Flask, request
import ast
import operator
import math
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Define a safe list of allowed operators
SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,  # Use truediv for float division
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
}

MAX_EQUATION_LENGTH = 200  # Limit equation length
MAX_NESTING_DEPTH = 10  # Limit expression complexity
MAX_EXPONENT = 10 # Limit exponent value
MAX_RESULT = 1e10  # Limit result magnitude


def safe_eval(expression, depth=0):
    """
    Safely evaluates a mathematical expression string.

    Args:
        expression: The mathematical expression string to evaluate.
        depth: Current nesting depth (for recursion).

    Returns:
        The result of the evaluation, or None if the expression is unsafe.
    """
    if depth > MAX_NESTING_DEPTH:
        logging.warning(f"Equation exceeded maximum nesting depth: {expression}")
        return None  # Prevent stack overflow

    try:
        node = ast.parse(expression, mode='eval')
    except SyntaxError:
        logging.warning(f"Syntax error in equation: {expression}")
        return None  # Handle syntax errors in the expression

    def eval_node(node, depth=0):
        if depth > MAX_NESTING_DEPTH:
            logging.warning("Maximum nesting depth exceeded during evaluation.")
            return None

        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.BinOp):
            op = SAFE_OPS.get(type(node.op))
            if op is None:
                logging.warning(f"Unsafe operator: {type(node.op)}")
                return None  # Disallow unsafe operators
            left = eval_node(node.left, depth + 1)
            right = eval_node(node.right, depth + 1)
            if left is None or right is None:
                return None  # Disallow unsafe operands
            try:
                result = op(left, right)
                if isinstance(node.op, ast.Pow):
                    if right > MAX_EXPONENT:
                        logging.warning(f"Exponent too large: {right}")
                        return None
                    if not -MAX_RESULT < result < MAX_RESULT:  # Check for overflow
                        logging.warning(f"Potential integer overflow detected in power operation: {result}")
                        return None
                    if math.isinf(result) or math.isnan(result):
                        logging.warning(f"Infinite or NaN result detected in power operation: {result}")
                        return None
                return result
            except ZeroDivisionError:
                logging.warning(f"Division by zero detected.")
                return None # Handle division by zero
            except OverflowError:
                logging.warning("OverflowError during calculation.")
                return None
        elif isinstance(node, ast.UnaryOp):
            op = SAFE_OPS.get(type(node.op))
            if op is None:
                logging.warning(f"Unsafe unary operator: {type(node.op)}")
                return None
            operand = eval_node(node.operand, depth + 1)
            if operand is None:
                return None
            return op(operand)
        else:
            logging.warning(f"Unsafe node type: {type(node)} in equation: {expression}")
            return None  # Disallow other node types (e.g., function calls, variables)

    return eval_node(node.body, depth)


@app.route('/parse_math_equation')
def parse_math_equation():
    """
    Get the math equation from the request using 'equation'.
    Evaluate it safely.
    Return the result of the evaluation as a string.
    """
    equation = request.args.get('equation')

    if not equation:
        return "Error: No equation provided.", 400

    equation = equation.strip()  # Remove leading/trailing whitespace
    if not equation:
        return "Error: Empty equation provided.", 400

    # Character Whitelisting (Example)
    allowed_chars = "0123456789+-*/(). "
    if not all(c in allowed_chars for c in equation):
        return "Error: Invalid characters in equation.", 400

    if len(equation) > MAX_EQUATION_LENGTH:
        return "Error: Equation too long.", 400

    result = safe_eval(equation)

    if result is None:
        return "Error: Invalid or unsafe equation.", 400

    return str(result)


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

