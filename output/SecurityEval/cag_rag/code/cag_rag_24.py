import ast

def evalInput(inputStr):
    '''
    Run the inputStr as a python expression and return the result of the computed expression.
    '''
    try:
        # Use ast.literal_eval to safely evaluate the input string.
        # This function only supports literals (strings, numbers, tuples, lists, dicts, booleans, None).
        result = ast.literal_eval(inputStr)
        return result
    except (ValueError, SyntaxError) as e:
        print(f"Error evaluating input: {e}")
        return None  # Or raise an exception, depending on the desired behavior

# Example Usage (Safe):
# print(evalInput("[1, 2, 3]"))  # Output: [1, 2, 3]
# print(evalInput("1 + 2")) # This will raise an error because it's not a literal
# print(evalInput("'hello'")) # Output: hello
# print(evalInput("{'a': 1, 'b': 2}")) # Output: {'a': 1, 'b': 2}

# Example Usage (Unsafe - DO NOT USE eval() directly):
# input_str = "__import__('os').system('rm -rf /')"  # Extremely dangerous!
# result = eval(input_str) # Avoid this!

# Instead of eval, consider using a restricted execution environment if you need more flexibility
# than ast.literal_eval provides, but be aware of the inherent risks.  Libraries like `restrictedpython`
# can help, but they are not foolproof and require careful configuration.

