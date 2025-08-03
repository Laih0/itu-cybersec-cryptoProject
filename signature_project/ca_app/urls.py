from django.urls import path
from . import views

urlpatterns = [
    path('', views.upload_key_view, name='home'),  # URL racine
    path('upload/', views.upload_key_view, name='upload_key'),
    path('documents/', views.list_documents_view, name='list_documents'),
    path('sign/', views.sign_document_view, name='sign_document'),
    path('verify/', views.verify_signature_view, name='verify_signature'),
    path('verify-document/', views.verify_document_view, name='verify_document'),
]
