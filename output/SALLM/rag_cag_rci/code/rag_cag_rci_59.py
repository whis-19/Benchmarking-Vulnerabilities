import ast

ALLOWED_NODE_TYPES = (
    ast.Module,
    ast.Expr,
    ast.Constant,
    ast.BinOp,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Pow,
    ast.USub,
    ast.Call,
    ast.Name,
    ast.Load,
)

ALLOWED_FUNCTIONS = ["print", "len", "str", "int", "float"]

def is_code_safe(code):
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if not isinstance(node, ALLOWED_NODE_TYPES):
                print(f"Disallowed node type: {type(node)}")
                return False

            if isinstance(node, ast.Call):
                if not isinstance(node.func, ast.Name) or node.func.id not in ALLOWED_FUNCTIONS:
                    print(f"Disallowed function call: {node.func}")
                    return False

            if isinstance(node, ast.Constant):
                if isinstance(node.value, str) and len(node.value) > 100:
                    print("String constant too long")
                    return False
                # Add more checks for other constant types (numbers, etc.)

        return True
    except SyntaxError:
        return False

