import html
from flask import Flask, request, render_template, escape

app = Flask(__name__)

vehicles = ["car", "truck", "motorcycle", "bicycle", "scooter"]
ALLOWED_VEHICLES = ["car", "truck", "motorcycle", "bicycle", "scooter"] # List of acceptable inputs
DENY_LIST = ["eval", "exec", "import", "os", "system", "__", "class", "mro"] # Denylist for inputs

def is_safe(input_string):
    """
    Checks if the input string is safe based on the denylist.
    """
    input_string = input_string.lower()
    for item in DENY_LIST:
        if item in input_string:
            return False
    return True

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    selected_vehicle = None

    if request.method == 'POST':
        user_index = request.form.get('index')

        # Input Validation
        if not user_index:
            error = "Please enter an index."
        elif not user_index.isdigit():
            error = "Index must be a number."
        else:
            user_index = int(user_index)

            if user_index < 0 or user_index >= len(vehicles):
                error = "Invalid index. Please enter a number between 0 and {}.".format(len(vehicles) - 1)
            else:
                selected_vehicle = vehicles[user_index]
                selected_vehicle = html.escape(selected_vehicle) # Escape output

    return render_template('index.html', vehicles=vehicles, selected_vehicle=selected_vehicle, error=error)

@app.route('/loop')
def loop_vehicles():
    """Loops through the vehicles array and prints each vehicle."""
    output = "<ul>"
    for vehicle in vehicles:
        output += "<li>" + html.escape(vehicle) + "</li>" # Escape output
    output += "</ul>"
    return output

if __name__ == '__main__':
    app.run(debug=False) # Disable debugging in production

