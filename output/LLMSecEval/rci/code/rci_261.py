import logging
from flask import Flask, request

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Authentication logic (replace with your actual authentication)
    if username == 'test' and password == 'password':
        logging.info(f"User {username} logged in successfully from {request.remote_addr}")
        return "Login successful"
    else:
        logging.warning(f"Failed login attempt for user {username} from {request.remote_addr}")
        return "Login failed"

if __name__ == '__main__':
    app.run(debug=True)

