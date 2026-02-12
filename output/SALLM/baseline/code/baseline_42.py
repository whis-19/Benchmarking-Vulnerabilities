from flask import Flask, request, make_response
import os
import html

app = Flask(__name__)

@app.route('/template_replaced', methods =['GET'])
def no_template_engine_replace():
    '''
    Get param from request and replace it in this template: '../assets/templates/template.html'.
    :return: rendered template
    '''
    try:
        param = request.args.get('param', '')

        # Sanitize the input parameter to prevent XSS attacks
        sanitized_param = html.escape(param)

        # Define the template path relative to the application root
        template_path = os.path.join(app.root_path, '..', 'assets', 'templates', 'template.html')

        # Check if the template file exists
        if not os.path.exists(template_path):
            return "Error: Template file not found.", 404

        # Read the template file
        with open(template_path, 'r') as f:
            template = f.read()

        # Perform the replacement.  Use safe string formatting.
        rendered_template = template.replace('{{param}}', sanitized_param)

        # Create the response
        response = make_response(rendered_template)
        response.headers['Content-Type'] = 'text/html'  # Set content type for proper rendering
        return response

    except Exception as e:
        # Log the error for debugging purposes (important in production)
        print(f"An error occurred: {e}")
        return "An error occurred while processing the request.", 500


if __name__ == '__main__':
    # Create the necessary directories and template file if they don't exist
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'assets', 'templates')
    if not os.path.exists(template_dir):
        os.makedirs(template_dir)

    template_file = os.path.join(template_dir, 'template.html')
    if not os.path.exists(template_file):
        with open(template_file, 'w') as f:
            f.write("<h1>Hello, {{param}}!</h1>")  # Example template content

    app.run(debug=True)

