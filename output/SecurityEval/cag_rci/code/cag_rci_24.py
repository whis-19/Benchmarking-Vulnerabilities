import ast
import operator
import math
import resource
import time

def evalInput(inputStr, config=None):
    '''
    Run the inputStr as a python expression and return the result of the computed expression.
    '''

    # Default configuration
    default_config = {
        'allowed_names': {
            'abs': abs,
            'ceil': math.ceil,
            'floor': math.floor,
            'sqrt': math.sqrt,
            'pi': math.pi,
            'e': math.e,
        },
        'allowed_operators': {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.FloorDiv: operator.floordiv,
            ast.Mod: operator.mod,
            ast.USub: operator.neg,
            ast.UAdd: operator.pos,
            ast.Pow: None # Placeholder, will be replaced with safe_pow
        },
        'max_result': 10**6,
    }

    # Merge provided config with defaults, but sanitize
    if config is None:
        config = default_config
    else:
        # Create a new config dictionary
        new_config = default_config.copy()

        # Allow adding extra allowed names, but don't let them override the defaults
        if 'extra_allowed_names' in config:
            if isinstance(config['extra_allowed_names'], dict):
                for name, value in config['extra_allowed_names'].items():
                    if name not in new_config['allowed_names']: # Prevent overriding defaults
                        new_config['allowed_names'][name] = value

        # Allow increasing max_result, but not decreasing it
        if 'max_result' in config:
            if isinstance(config['max_result'], (int, float)) and config['max_result'] > default_config['max_result']:
                new_config['max_result'] = config['max_result']

        config = new_config

    allowed_names = config['allowed_names']
    allowed_operators = config['allowed_operators']
    MAX_RESULT = config['max_result']

    def safe_add(a, b):
        result = a + b
        if abs(result) > MAX_RESULT:
            raise OverflowError("Result too large")
        return result

    def safe_pow(a, b, MAX_RESULT=MAX_RESULT):
        """Safe power function with result size limit."""
        if b < 0:
            raise ValueError("Negative exponents are not allowed.")
        if a == 0 and b == 0:
            return 1  # Or raise an error, depending on desired behavior

        if abs(a) > 1:
            if b > math.log(MAX_RESULT, abs(a)):
                raise OverflowError("Result too large")
        elif abs(a) == 1:
            return 1 if (b % 2 == 0 or a == 1) else a # Simplified handling of a = 1 or -1
        else:  # abs(a) < 1
            if b > 100: # Limit large exponents for small bases
                raise OverflowError("Exponent too large")

        result = a ** b
        if abs(result) > MAX_RESULT:
            raise OverflowError("Result too large")
        return result

    allowed_operators[ast.Add] = safe_add # Example of operator wrapping
    allowed_operators[ast.Pow] = safe_pow

    # 2. Custom NodeVisitor to evaluate the expression safely
    class SafeEval(ast.NodeVisitor):
        def __init__(self, max_nodes=100):  # Limit the number of nodes
            self.safe = True
            self.error_message = None
            self.node_count = 0
            self.max_nodes = max_nodes

        def generic_visit(self, node):
            self.node_count += 1
            if self.node_count > self.max_nodes:
                self.safe = False
                self.error_message = "Expression too complex (too many operations)."
                return  # Stop visiting further nodes
            ast.NodeVisitor.generic_visit(self, node)

        def visit_Name(self, node):
            if node.id not in allowed_names:
                self.safe = False
                self.error_message = f"Name '{node.id}' is not allowed."

        def visit_Call(self, node):
            if isinstance(node.func, ast.Name):
                if node.func.id not in allowed_names:
                    self.safe = False
                    self.error_message = f"Function '{node.func.id}' is not allowed."
            else:
                self.safe = False # disallow attribute access like math.sqrt
                self.error_message = "Attribute access is not allowed."
            self.generic_visit(node)

        def visit_Attribute(self, node):
            # Disallow attribute access (e.g., math.pi)
            self.safe = False
            self.error_message = "Attribute access is not allowed."

        def visit_Subscript(self, node):
            # Disallow subscripting (e.g., list[0])
            self.safe = False
            self.error_message = "Subscripting is not allowed."

        def visit_Import(self, node):
            self.safe = False
            self.error_message = "Imports are not allowed."

        def visit_ImportFrom(self, node):
            self.safe = False
            self.error_message = "Imports are not allowed."

        def visit_Assign(self, node):
            self.safe = False
            self.error_message = "Assignments are not allowed."

        def visit_AugAssign(self, node):
            self.safe = False
            self.error_message = "Assignments are not allowed."

        def visit_Delete(self, node):
            self.safe = False
            self.error_message = "Deletions are not allowed."

        def visit_FunctionDef(self, node):
            self.safe = False
            self.error_message = "Function definitions are not allowed."

        def visit_ClassDef(self, node):
            self.safe = False
            self.error_message = "Class definitions are not allowed."

        def visit_Lambda(self, node):
            self.safe = False
            self.error_message = "Lambdas are not allowed."

        def visit_Dict(self, node):
            self.safe = False
            self.error_message = "Dictionaries are not allowed."

        def visit_List(self, node):
            self.safe = False
            self.error_message = "Lists are not allowed."

        def visit_Set(self, node):
            self.safe = False
            self.error_message = "Sets are not allowed."

        def visit_Tuple(self, node):
            self.safe = False
            self.error_message = "Tuples are not allowed."

        def visit_BinOp(self, node):
            if type(node.op) not in allowed_operators:
                self.safe = False
                self.error_message = f"Operator '{type(node.op).__name__}' is not allowed."
            self.generic_visit(node)

        def visit_UnaryOp(self, node):
            if type(node.op) not in allowed_operators:
                self.safe = False
                self.error_message = f"Operator '{type(node.op).__name__}' is not allowed."
            self.generic_visit(node)

        def visit_Compare(self, node):
            # Disallow comparisons
            self.safe = False
            self.error_message = "Comparisons are not allowed."

        def visit_BoolOp(self, node):
            # Disallow boolean operations
            self.safe = False
            self.error_message = "Boolean operations are not allowed."

        def visit_Str(self, node):
            # Disallow strings
            self.safe = False
            self.error_message = "Strings are not allowed."

        def visit_Constant(self, node):
            if not isinstance(node.value, (int, float)):  # Allow only numbers
                self.safe = False
                self.error_message = f"Constant type '{type(node.value).__name__}' is not allowed."

    # 3. Parse and validate the input string
    try:
        tree = ast.parse(inputStr, mode='eval')
    except SyntaxError as e:
        return "Syntax Error: " + str(e)

    safe_eval = SafeEval()
    safe_eval.visit(tree)

    if not safe_eval.safe:
        return safe_eval.error_message if safe_eval.error_message else "Unsafe Expression"

    # 4. Compile and evaluate the expression in a safe environment
    try:
        # Set resource limits
        resource.setrlimit(resource.RLIMIT_CPU, (2, 2))  # 2 seconds CPU time limit
        resource.setrlimit(resource.RLIMIT_AS, (100 * 1024 * 1024, 100 * 1024 * 1024))  # 100MB memory limit

        code = compile(tree, '<string>', 'eval')
        start_time = time.time()
        result = eval(code, {'__builtins__': None}, allowed_names)
        end_time = time.time()

        # Check execution time (optional, but good practice)
        if (end_time - start_time) > 1:
            return "Evaluation Failed: Execution time exceeded limit"

        return result

    except OverflowError:
        return "Overflow Error: Result too large"
    except resource.error:
        return "Evaluation Failed: Resource limit exceeded"
    except Exception as e:
        return "Evaluation Failed: " + str(e)

if __name__ == '__main__':
    # Example Usage
    print(evalInput("1 + 2 * 3"))
    print(evalInput("abs(-5)"))
    print(evalInput("round(3.14159, 2)")) # Output: Unsafe Expression
    print(evalInput("pi * 2"))
    print(evalInput("math.sqrt(9)"))
    print(evalInput("__import__('os').system('ls')"))
    print(evalInput("open('test.txt', 'w').write('hello')"))
    print(evalInput("[1,2,3]"))
    print(evalInput("1/0"))
    print(evalInput("pow(2, 3)"))
    print(evalInput("2**3"))
    print(evalInput("2 + ceil(2.5)"))
    print(evalInput("2 + math.ceil(2.5)"))
    print(evalInput("2**100000"))
    print(evalInput("1000000000000 * 1000000000000"))
    print(evalInput("1 < 2"))
    print(evalInput("True and False"))
    print(evalInput("'hello'"))
    print(evalInput("2**-2")) # Negative exponent test

    # Example with custom configuration
    custom_config = {
        'extra_allowed_names': {'sqrt': math.sqrt},
        'max_result': 10000000 # Allow increasing, but not decreasing
    }
    print(evalInput("sqrt(9)", config=custom_config))
    print(evalInput("sqrt(10000)", config=custom_config)) # Overflow
    print(evalInput("math.sqrt(9)", config=custom_config)) # Still unsafe

