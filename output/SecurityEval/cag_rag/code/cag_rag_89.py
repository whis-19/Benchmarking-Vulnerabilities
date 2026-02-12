from django.shortcuts import render
   from .utils import http_responser_redirect  # Assuming you put the code in utils.py

   def my_view(request):
       # ... your view logic ...
       return http_responser_redirect(request)

