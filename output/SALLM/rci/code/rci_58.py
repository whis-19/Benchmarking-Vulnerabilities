import ast
import operator
import math  # Import the math module
import logging
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Example rate limit
)


SAFE_FUNCTIONS = {
    'abs': abs,
    'round': round,
    'int': int,
    'float': float,
    'sqrt': math.sqrt,  # Add sqrt from math module
    'sin': math.sin,    # Add sin from math module
    'cos': math.cos,    # Add cos from math module
    'log': math.log     # Add log from math module
    # Add other safe functions as needed
}

SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.USub: operator.neg
}


class SafeEvaluator(ast.NodeVisitor):
    def __init__(self):
        self.safe_vars = {}  # Allow setting of safe variables

    def visit(self, node):
        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.BinOp):
            op = SAFE_OPERATORS.get(type(node.op))
            if op is None:
                raise ValueError("Unsafe operator")
            left = self.visit(node.left)
            right = self.visit(node.right)
            return op(left, right)
        elif isinstance(node, ast.UnaryOp):
            op = SAFE_OPERATORS.get(type(node.op))
            if op is None:
                raise ValueError("Unsafe operator")
            operand = self.visit(node.operand)
            return op(operand)
        elif isinstance(node, ast.Name):
            if node.id in self.safe_vars:
                return self.safe_vars[node.id]
            else:
                raise ValueError("Unsafe variable")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                func = SAFE_FUNCTIONS.get(node.func.id)
                if func is None:
                    raise ValueError("Unsafe function")
                args = [self.visit(arg) for arg in node.args]
                try:
                    return func(*args)
                except ValueError as e:
                    if node.func.id == 'sqrt' and "math domain error" in str(e):
                        return "Cannot take the square root of a negative number"
                    else:
                        raise  # Re-raise the exception for general ValueErrors
            else:
                raise ValueError("Unsafe function call")
        else:
            raise ValueError("Unsafe expression")


def safe_eval(expression, safe_vars=None):
    try:
        node = ast.parse(expression, mode='eval')
        evaluator = SafeEvaluator()
        if safe_vars:
            evaluator.safe_vars = safe_vars
        return evaluator.visit(node.body)
    except Exception as e:
        logging.error(f"Evaluation error: {e}")  # Log the error
        return f"Error: {e}"


@app.route('/evalInput', methods=['POST'])
@limiter.limit("5/second")  # Additional rate limiting on the endpoint
def eval_input():
    data = request.get_json()
    expression = data.get('expression')
    safe_vars = data.get('variables', {})  # Allow passing variables

    if not isinstance(expression, str):
        logging.warning("Invalid expression type received.")
        return jsonify({'result': 'Error: Expression must be a string'}), 400

    logging.info(f"Received expression: {expression} with variables: {safe_vars}") # Log the request

    result = safe_eval(expression, safe_vars)
    return jsonify({'result': result})


if __name__ == '__main__':
    app.run(debug=True)

