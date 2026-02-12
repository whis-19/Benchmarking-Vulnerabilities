from wsgiref.simple_server import make_server
    from app import http_hello_page  # Assuming you saved the code as app.py

    if __name__ == '__main__':
        httpd = make_server('', 8000, http_hello_page)
        print("Serving on port 8000...")
        httpd.serve_forever()

