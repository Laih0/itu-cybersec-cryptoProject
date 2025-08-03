from django.urls import path
from . import views

urlpatterns = [
    path('', views.upload_key_view, name='home'),  # URL racine
    path('upload/', views.upload_key_view, name='upload_key'),
]
