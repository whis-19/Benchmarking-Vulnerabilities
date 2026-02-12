from flask import Flask
    from flask_cors import CORS

    app = Flask(__name__)
    CORS(app, origins=["https://example.com", "https://anotherdomain.com"]) # Replace with your actual origins

