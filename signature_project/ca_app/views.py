import json
import os
import hashlib
import base64
from datetime import datetime
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from .forms import PublicKeyUploadForm

def register_user(username, public_key_pem, registry_path="registry.json"):
    try:
        with open(registry_path, "r") as f:
            registry = json.load(f)
    except FileNotFoundError:
        registry = {}

    registry[username] = public_key_pem

    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=2)

def upload_key_view(request):
    if request.method == 'POST':
        form = PublicKeyUploadForm(request.POST, request.FILES)
        if form.is_valid():
            username = form.cleaned_data['username']
            public_key_file = request.FILES['public_key_file']
            public_key_pem = public_key_file.read().decode('utf-8')
            register_user(username, public_key_pem)
            return render(request, 'ca_app/success.html', {'username': username})
    else:
        form = PublicKeyUploadForm()
    return render(request, 'ca_app/upload.html', {'form': form})

def list_documents_view(request):
    """Affiche la liste des fichiers .txt disponibles pour signature"""
    # Chercher les fichiers .txt dans le répertoire du projet
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    txt_files = []
    
    for file in os.listdir(base_dir):
        if file.endswith('.txt'):
            txt_files.append(file)
    
    return render(request, 'ca_app/documents.html', {'txt_files': txt_files})

def sign_document_view(request):
    """Gère la signature d'un document"""
    if request.method == 'POST':
        filename = request.POST.get('filename')
        username = request.POST.get('username')
        
        if not filename or not username:
            return JsonResponse({'error': 'Nom de fichier et utilisateur requis'}, status=400)
        
        try:
            # Lire le fichier document.txt
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            file_path = os.path.join(base_dir, filename)
            
            if not os.path.exists(file_path):
                return JsonResponse({'error': 'Fichier non trouvé'}, status=404)
            
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Calculer le hash SHA-256
            hash_value = hashlib.sha256(file_content).digest()
            
            # Charger la clé privée de l'utilisateur
            private_key_path = os.path.join(base_dir, f"{username}_private.pem")
            if not os.path.exists(private_key_path):
                return JsonResponse({'error': f'Clé privée non trouvée pour {username}'}, status=404)
            
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            
            # Signer le hash avec RSA-PSS
            signature = private_key.sign(
                hash_value,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Encoder la signature en base64
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            # Créer les métadonnées de signature
            signature_data = {
                "user": username,
                "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "signature": signature_b64
            }
            
            # Sauvegarder dans un fichier .sig
            sig_filename = f"{filename}.sig"
            sig_path = os.path.join(base_dir, sig_filename)
            
            with open(sig_path, 'w') as f:
                json.dump(signature_data, f, indent=2)
            
            return JsonResponse({
                'success': True,
                'message': f'Document signé avec succès! Signature sauvegardée dans {sig_filename}',
                'signature_file': sig_filename
            })
            
        except Exception as e:
            return JsonResponse({'error': f'Erreur lors de la signature: {str(e)}'}, status=500)
    
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)
