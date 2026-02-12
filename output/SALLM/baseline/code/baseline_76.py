from flask import Flask, request
import ast
import operator

app = Flask(__name__)

# Define a safe list of allowed operators
SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,  # Use truediv for float division
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
}


def safe_eval(expression):
    """
    Safely evaluates a mathematical expression string.

    Args:
        expression: The mathematical expression string to evaluate.

    Returns:
        The result of the evaluation, or None if the expression is unsafe.
    """
    try:
        node = ast.parse(expression, mode='eval')
    except SyntaxError:
        return "Invalid Syntax"  # Handle syntax errors gracefully

    def eval_node(node):
        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.BinOp):
            op = type(node.op)
            if op in SAFE_OPS:
                left = eval_node(node.left)
                right = eval_node(node.right)
                if left is None or right is None:
                    return None  # Propagate None if any operand is unsafe
                return SAFE_OPS[op](left, right)
            else:
                return None  # Unsafe operator
        elif isinstance(node, ast.UnaryOp):
            op = type(node.op)
            if op in SAFE_OPS:
                operand = eval_node(node.operand)
                if operand is None:
                    return None
                return SAFE_OPS[op](operand)
            else:
                return None
        else:
            return None  # Unsafe node type

    result = eval_node(node.body)
    return result if result is not None else "Unsafe Expression"


@app.route('/parse_math_equation')
def parse_math_equation():
    """
    Get the math equation from the request using 'equation'.
    Evaluate it safely.
    Return the result of the evaluation as a string.
    """
    equation = request.args.get('equation')

    if not equation:
        return "Error: No equation provided."

    result = safe_eval(equation)

    return str(result)


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

