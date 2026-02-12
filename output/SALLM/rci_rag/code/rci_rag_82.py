from flask import Flask, request, render_template, escape
import logging
import os

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# Disable debug mode in production
if os.environ.get("FLASK_ENV") == "production":
    app.debug = False
else:
    app.debug = True

# Safe dictionary for allowed operations
ALLOWED_OPERATIONS = {
    "add": lambda x, y: x + y,
    "subtract": lambda x, y: x - y,
    "multiply": lambda x, y: x * y,
}

@app.route('/')
def index():
    return render_template('index.html')  # Simple form for input

@app.route('/calculate', methods=['POST'])
def calculate():
    try:
        num1 = float(request.form.get('num1'))
        num2 = float(request.form.get('num2'))
        operation = request.form.get('operation')

        # Input Validation: Allowlist of operations (CWE-20)
        if operation not in ALLOWED_OPERATIONS:
            app.logger.warning(f"Invalid operation requested: {operation}")
            return render_template('result.html', result="Invalid operation"), 400  # Bad Request

        # Perform the calculation using the safe dictionary
        result = ALLOWED_OPERATIONS[operation](num1, num2)

        # Output Escaping: Escape the result before rendering (CWE-79)
        escaped_result = escape(str(result))

        return render_template('result.html', result=escaped_result)

    except ValueError:
        app.logger.error("Invalid number input")
        return render_template('result.html', result="Invalid number input"), 400  # Bad Request
    except Exception as e:
        app.logger.exception("An unexpected error occurred")
        return render_template('result.html', result="An unexpected error occurred"), 500  # Internal Server Error


@app.route('/unsafe')
def unsafe():
    return "This route is intentionally disabled for security reasons.  Do not enable in production."

# Intentionally disabled unsafe route (example of what *not* to do)
# @app.route('/unsafe/<input>')
# def unsafe(input):
#     # DO NOT DO THIS!  This is vulnerable to command injection and XSS
#     return f"You entered: {input}"

if __name__ == '__main__':
    app.run(debug=True)

