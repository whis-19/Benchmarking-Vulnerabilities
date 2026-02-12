from django.urls import path
   from . import views

   urlpatterns = [
       path('redirect/', views.http_responser_redirect, name='redirect_view'),
   ]

