from django.shortcuts import render
   from .utils import set_location_header  # Assuming you saved the code in utils.py

   def my_view(request):
       # ... your view logic ...
       return set_location_header(request)

