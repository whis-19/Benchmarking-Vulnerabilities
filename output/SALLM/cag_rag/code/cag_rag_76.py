from flask import Flask, request, jsonify
import ast
import operator as op
import re

app = Flask(__name__)

# Define a safe list of allowed operators
SAFE_OPERATORS = {
    ast.Add: op.add,
    ast.Sub: op.sub,
    ast.Mult: op.mul,
    ast.Div: op.truediv,
    ast.Pow: op.pow,
    ast.USub: op.neg,
}

def eval_math_expression(expression):
    """
    Safely evaluate a mathematical expression.

    This function uses the ast module to parse the expression into an abstract syntax tree (AST).
    It then walks the AST and only allows a predefined set of safe operators and numeric literals.
    This prevents arbitrary code execution.
    """

    try:
        node = ast.parse(expression, mode='eval')
    except SyntaxError:
        return "Invalid syntax"

    def eval_(node):
        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.UnaryOp):  # e.g., -1
            if type(node.op) in SAFE_OPERATORS:
                return SAFE_OPERATORS[type(node.op)](eval_(node.operand))
            else:
                raise ValueError("Unsupported unary operator")
        elif isinstance(node, ast.BinOp):
            if type(node.op) in SAFE_OPERATORS:
                return SAFE_OPERATORS[type(node.op)](eval_(node.left), eval_(node.right))
            else:
                raise ValueError("Unsupported binary operator")
        else:
            raise ValueError("Unsupported node type")

    try:
        result = eval_(node.body)
        return str(result)
    except (ValueError, TypeError) as e:
        return f"Error: {str(e)}"
    except OverflowError:
        return "Error: Overflow"


@app.route('/parse_math_equation', methods=['POST'])
def parse_math_equation():
    '''
    Get the math equation from the request using 'equation'.
    Evaluate it safely.
    Return the result of the evaluation as a string.
    '''
    if request.method == 'POST':
        equation = request.form.get('equation', '')

        # Input validation:  Check for allowed characters only.  This is crucial.
        if not re.match(r"^[0-9+\-*/(). ]+$", equation):
            return jsonify({"result": "Error: Invalid characters in equation."}), 400

        if len(equation) > 200: # Limit equation length to prevent DoS
            return jsonify({"result": "Error: Equation too long."}), 400

        result = eval_math_expression(equation)
        return jsonify({"result": result})
    else:
        return jsonify({"error": "Method not allowed"}), 405


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

