import re
import html
from flask import Flask, request, render_template
from flask_wtf.csrf import CSRFProtect  # Import CSRF protection

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Required for CSRF protection and session management
csrf = CSRFProtect(app)  # Enable CSRF protection

vehicles = ["car", "truck", "motorcycle", "bicycle", "scooter"]

@app.route('/', methods=['GET', 'POST'])
def index():
    error_message = None
    selected_vehicle = None

    if request.method == 'POST':
        user_input = request.form.get('vehicle_index')

        # --- Input Validation ---

        # 1. Check for missing input
        if not user_input:
            error_message = "Error: Please enter an index."
            return render_template('index.html', vehicles=vehicles, error_message=error_message, selected_vehicle=None)

        # 2. Input Type Validation and Regular Expression for Integer Check
        if not re.match(r"^\d+$", user_input):
            error_message = "Error: Invalid input. Please enter a valid integer index."
            return render_template('index.html', vehicles=vehicles, error_message=error_message, selected_vehicle=None)

        # 3. Input Length Validation
        if len(user_input) > 3:  # Limit to 3 digits (max index 999)
            error_message = "Error: Index is too large."
            return render_template('index.html', vehicles=vehicles, error_message=error_message, selected_vehicle=None)

        # 4. Denylist (Consider removing or making configurable)
        denylist = ["-1", "-2", "-3"]  # Add more as needed
        if user_input in denylist:
            error_message = "Error: Invalid index."
            return render_template('index.html', vehicles=vehicles, error_message=error_message, selected_vehicle=None)

        # 5. Acceptable Inputs (Range Check)
        try:
            index = int(user_input)
            if 0 <= index < len(vehicles):
                selected_vehicle = vehicles[index]
            else:
                error_message = "Error: Index out of bounds."

        except ValueError: #Catch any other unexpected errors during conversion
            error_message = "Error: Invalid input. Please enter a valid integer index."
        except Exception as e:
            app.logger.error(f"Unexpected error: {e}")
            error_message = "Error: An unexpected error occurred."


    return render_template('index.html', vehicles=vehicles, error_message=error_message, selected_vehicle=selected_vehicle)


@app.template_filter('escape_html')
def escape_html_filter(text):
    """Custom filter to escape HTML entities."""
    return html.escape(text)


app.jinja_env.filters['escape_html'] = escape_html_filter #Register the filter

if __name__ == '__main__':
    # IMPORTANT:  Disable debugging in production!
    app.run(debug=False)

