import magic
import os
import time
from urllib.parse import urlparse
import requests
import validators
import uuid
from defusedxml.lxml import fromstring, ParseError
from flask import Flask, request, Response
from lxml import etree  # For XSD validation

app = Flask(__name__)

# Security Configuration
ALLOWED_DOMAINS = ["example.com", "api.example.org"]
ALLOWED_PATHS = {
    "example.com": ["/api/data", "/images"],  # Example: Only allow specific paths
    "api.example.org": ["/v1/users", "/v1/products"]
}
ALLOWED_FILE_EXTENSIONS = [".xml"]
UPLOAD_DIRECTORY = "uploads"
MAX_FILE_SIZE = 1024 * 1024  # 1MB
MAX_UPLOAD_RATE = 5  # Max 5 uploads per minute per IP
UPLOAD_RATE_LIMIT_WINDOW = 60  # Seconds

os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

# Rate Limiting (Simple in-memory implementation - consider a more robust solution for production)
upload_counts = {}

def is_rate_limited(ip_address):
    now = time.time()
    if ip_address not in upload_counts:
        upload_counts[ip_address] = []
    
    # Remove old entries
    upload_counts[ip_address] = [t for t in upload_counts[ip_address] if now - t < UPLOAD_RATE_LIMIT_WINDOW]
    
    if len(upload_counts[ip_address]) >= MAX_UPLOAD_RATE:
        return True
    
    upload_counts[ip_address].append(now)
    return False

def is_valid_url(url):
    """
    Validates a URL against an allowlist of domains and paths, and using validators library.
    """
    try:
        result = urlparse(url)
        if result.netloc not in ALLOWED_DOMAINS or result.scheme not in ("http", "https"):
            return False

        # Check allowed paths
        if result.netloc in ALLOWED_PATHS:
            allowed_paths = ALLOWED_PATHS[result.netloc]
            if not any(result.path.startswith(path) for path in allowed_paths):
                return False

        if not validators.url(url):
            return False

        # DNS Rebinding Check (Basic - not foolproof)
        initial_ip = socket.gethostbyname(result.netloc)
        time.sleep(0.1)  # Give time for DNS to potentially change
        current_ip = socket.gethostbyname(result.netloc)
        if initial_ip != current_ip:
            app.logger.warning(f"Possible DNS rebinding detected for {url}")
            return False

        return True
    except Exception as e:
        app.logger.error(f"URL validation error: {e}")
        return False

def is_valid_file_extension(filename):
    """
    Validates the file extension against an allowlist.
    """
    return any(filename.lower().endswith(ext) for ext in ALLOWED_FILE_EXTENSIONS)

def is_valid_file_type(filepath):
    """
    Validates the file type based on its content using python-magic.
    """
    try:
        mime = magic.Magic(mime=True)
        file_mime_type = mime.from_file(filepath)
        allowed_mime_types = ["application/xml", "text/xml"]
        return file_mime_type in allowed_mime_types
    except Exception as e:
        app.logger.error(f"Error determining file type: {e}")
        return False

def validate_xml(xml_string, schema_path=None):
    """
    Validates that the XML string is well-formed and optionally validates against an XSD schema.
    """
    try:
        root = fromstring(xml_string)

        if schema_path:
            try:
                xmlschema_doc = etree.parse(schema_path)
                xmlschema = etree.XMLSchema(xmlschema_doc)
                xmlschema.assertValid(root)  # Raises lxml.etree.DocumentInvalid if invalid
            except etree.XMLSchemaParseError as e:
                app.logger.error(f"Error parsing XSD schema: {e}")
                return False
            except etree.DocumentInvalid as e:
                app.logger.error(f"XML validation against schema failed: {e}")
                return False

        return True
    except ParseError:
        return False

def fetch_url_content(url):
    try:
        response = requests.get(url, verify=True, timeout=10, headers={'User-Agent': 'MyWebApp/1.0'})
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        error_message = "Error fetching URL."
        app.logger.error(f"Error fetching URL {url}: {e}")
        raise Exception(error_message)

import socket

@app.route("/upload", methods=["GET", "POST"])
def upload():
    client_ip = request.remote_addr  # Get the client's IP address

    if is_rate_limited(client_ip):
        return Response("Too many uploads. Please try again later.", status=429)  # HTTP 429 Too Many Requests

    if request.method == "POST":
        if "xml_url" in request.form:
            xml_url = request.form["xml_url"]

            if not is_valid_url(xml_url):
                return Response("Invalid URL.", status=400)

            try:
                xml_data = fetch_url_content(xml_url)
            except Exception as e:
                return Response(f"Error fetching URL: {e}", status=400)

        elif "xml_file" in request.files:
            xml_file = request.files["xml_file"]

            if xml_file.filename == "":
                return Response("No file selected.", status=400)

            if not is_valid_file_extension(xml_file.filename):
                return Response("Invalid file extension.", status=400)

            xml_file.seek(0, os.SEEK_END)
            file_length = xml_file.tell()
            xml_file.seek(0)

            if file_length > MAX_FILE_SIZE:
                return Response("File size exceeds the maximum allowed size.", status=413)

            # Generate a random filename with retry logic
            max_retries = 3
            for i in range(max_retries):
                filename = str(uuid.uuid4()) + ".xml"
                filepath = os.path.join(UPLOAD_DIRECTORY, filename)

                if not os.path.exists(filepath):  # Check if the file already exists
                    break  # Filename is unique
                else:
                    app.logger.warning(f"Filename collision detected: {filename}. Retrying...")
                    time.sleep(0.1 * (i + 1))  # Exponential backoff

            else:  # If loop completes without finding a unique filename
                app.logger.error("Failed to generate a unique filename after multiple retries.")
                return Response("Failed to save file due to filename collision.", status=500)

            if not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_DIRECTORY)):
                return Response("Invalid file path.", status=400)

            try:
                xml_file.save(filepath)
                os.chmod(filepath, 0o440)  # Set file permissions

                if not is_valid_file_type(filepath):
                    os.remove(filepath)
                    return Response("Invalid file type.", status=400)

                with open(filepath, "r") as f:
                    xml_data = f.read()

            except Exception as e:
                app.logger.error(f"Error saving file: {e}")
                return Response(f"Error saving file: {e}", status=500)

        else:
            return Response("Missing 'xml_url' or 'xml_file' parameter.", status=400)

        # Validate XML against schema (optional)
        schema_path = "schema.xsd"  # Replace with the actual path to your XSD schema
        if not validate_xml(xml_data, schema_path):
            return Response("Invalid XML data or XML does not conform to the schema.", status=400)

        try:
            root = ET.fromstring(xml_data)
            root_tag = root.tag
            return Response(f"XML Uploaded and Processed. Root tag: {root_tag}", status=200)

        except ET.ParseError as e:
            return Response(f"Error parsing XML: {e}", status=400)

    return """<!DOCTYPE html><html><head><title>XML Upload</title></head><body><h1>Upload XML</h1><form method="post" enctype="multipart/form-data"><h2>From URL:</h2><label for="xml_url">XML URL:</label><br><input type="url" id="xml_url" name="xml_url"><br><br><h2>From File:</h2><label for="xml_file">XML File:</label><br><input type="file" id="xml_file" name="xml_file"><br><br><input type="submit" value="Upload"></form></body></html>"""

if __name__ == "__main__":
    app.run(debug=True)

