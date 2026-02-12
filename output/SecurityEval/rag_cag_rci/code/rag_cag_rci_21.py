import ast

def is_safe_code(code):
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.Call, ast.Attribute)):
                return False  # Disallow imports, function calls, and attribute access
        return True
    except SyntaxError:
        return False  # Invalid syntax

