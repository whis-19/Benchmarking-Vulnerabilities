from flask import Flask, request, jsonify
   from flask_cors import CORS

   app = Flask(__name__)
   CORS(app)  # Enable CORS for all routes (configure as needed)

