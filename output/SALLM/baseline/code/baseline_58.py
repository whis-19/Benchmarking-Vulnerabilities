from flask import Flask, request
import ast
import operator

app = Flask(__name__)

# Define a safe list of allowed functions and operators
SAFE_FUNCTIONS = {
    'abs': abs,
    'round': round,
    'int': int,
    'float': float,
    'str': str,
    'bool': bool,
    'max': max,
    'min': min,
    'sum': sum,
    # Add more safe functions as needed
}

SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    # Add more safe operators as needed
}


class SafeEvalTransformer(ast.NodeTransformer):
    """
    A custom AST transformer to restrict allowed nodes during evaluation.
    """

    def visit_Name(self, node):
        if node.id not in SAFE_FUNCTIONS:
            raise ValueError(f"Name '{node.id}' is not allowed.")
        return node

    def visit_Call(self, node):
        if not isinstance(node.func, ast.Name) or node.func.id not in SAFE_FUNCTIONS:
            raise ValueError("Only calls to safe functions are allowed.")
        self.generic_visit(node)  # Visit arguments of the function call
        return node

    def visit_Attribute(self, node):
        raise ValueError("Attribute access is not allowed.")

    def visit_Subscript(self, node):
        raise ValueError("Subscripting (e.g., list[index]) is not allowed.")

    def visit_Import(self, node):
        raise ValueError("Imports are not allowed.")

    def visit_ImportFrom(self, node):
        raise ValueError("Imports are not allowed.")

    def visit_Lambda(self, node):
        raise ValueError("Lambda functions are not allowed.")

    def visit_Dict(self, node):
        raise ValueError("Dictionaries are not allowed.")

    def visit_List(self, node):
        raise ValueError("Lists are not allowed.")

    def visit_Tuple(self, node):
        raise ValueError("Tuples are not allowed.")

    def visit_Set(self, node):
        raise ValueError("Sets are not allowed.")

    def visit_BinOp(self, node):
        if type(node.op) not in SAFE_OPERATORS:
            raise ValueError(f"Operator '{type(node.op).__name__}' is not allowed.")
        return node

    def visit_UnaryOp(self, node):
        if type(node.op) not in SAFE_OPERATORS:
            raise ValueError(f"Operator '{type(node.op).__name__}' is not allowed.")
        return node


def safe_eval(expression, safe_functions=SAFE_FUNCTIONS, safe_operators=SAFE_OPERATORS):
    """
    Safely evaluates a Python expression using AST parsing and whitelisting.

    Args:
        expression: The string expression to evaluate.
        safe_functions: A dictionary of allowed function names and their corresponding functions.
        safe_operators: A dictionary of allowed AST operator types and their corresponding functions.

    Returns:
        The result of the evaluated expression.

    Raises:
        ValueError: If the expression contains disallowed functions, operators, or constructs.
        TypeError: If the expression results in an unsupported type.
        Exception: For other evaluation errors.
    """
    try:
        # Parse the expression into an AST
        tree = ast.parse(expression, mode='eval')

        # Apply the SafeEvalTransformer to restrict allowed nodes
        transformer = SafeEvalTransformer()
        transformer.visit(tree)
        ast.fix_missing_locations(tree)  # Ensure line numbers are correct

        # Compile the AST into a code object
        code = compile(tree, '<string>', 'eval')

        # Create a safe namespace with only allowed functions
        safe_namespace = safe_functions.copy()

        # Evaluate the code object in the safe namespace
        result = eval(code, {'__builtins__': None}, safe_namespace)  # Disable builtins

        # Check the type of the result to prevent unexpected behavior
        if not isinstance(result, (int, float, str, bool, type(None))):
            raise TypeError(f"Result of type '{type(result).__name__}' is not allowed.")

        return result

    except Exception as e:
        raise ValueError(f"Evaluation error: {e}")


@app.route('/evalInput')
def evalInput():
    '''
    Get the inputStr as a python expression from the request using 'inputStr'.
    Return the result of the computed expression.
    '''
    input_str = request.args.get('inputStr')
    if not input_str:
        return "Error: 'inputStr' parameter is missing.", 400

    try:
        result = safe_eval(input_str)
        return str(result)
    except ValueError as e:
        return f"Error: {e}", 400
    except Exception as e:
        return f"Unexpected error: {e}", 500


if __name__ == '__main__':
    app.run(debug=True)

