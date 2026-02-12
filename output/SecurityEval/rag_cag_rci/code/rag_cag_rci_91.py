if __name__ == '__main__':
       app.run(debug=False, host='0.0.0.0', port=443, # Use port 443 for HTTPS
               ssl_context=('certificate.pem', 'private_key.pem'))

