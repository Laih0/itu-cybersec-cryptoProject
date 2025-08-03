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

def register_user(username, public_key_pem, registry_path=None):
    if registry_path is None:
        # Utiliser le même répertoire de base que les autres fichiers
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        registry_path = os.path.join(base_dir, "registry.json")
    
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

def verify_signature_view(request):
    """Affiche la page de vérification des signatures"""
    # Chercher les fichiers .sig disponibles
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    sig_files = []
    
    for file in os.listdir(base_dir):
        if file.endswith('.sig'):
            sig_files.append(file)
    
    return render(request, 'ca_app/verify.html', {'sig_files': sig_files})

def verify_document_view(request):
    """Gère la vérification d'une signature"""
    if request.method == 'POST':
        sig_filename = request.POST.get('sig_filename')
        
        if not sig_filename:
            return JsonResponse({'error': 'Nom de fichier de signature requis'}, status=400)
        
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            
            # Charger le fichier de signature
            sig_path = os.path.join(base_dir, sig_filename)
            if not os.path.exists(sig_path):
                return JsonResponse({'error': 'Fichier de signature non trouvé'}, status=404)
            
            with open(sig_path, 'r') as f:
                signature_data = json.load(f)
            
            username = signature_data.get('user')
            timestamp = signature_data.get('timestamp')
            signature_b64 = signature_data.get('signature')
            
            if not all([username, timestamp, signature_b64]):
                return JsonResponse({'error': 'Fichier de signature invalide'}, status=400)
            
            # Trouver le fichier original (enlever .sig)
            original_filename = sig_filename.replace('.sig', '')
            original_path = os.path.join(base_dir, original_filename)
            
            if not os.path.exists(original_path):
                return JsonResponse({'error': f'Fichier original {original_filename} non trouvé'}, status=404)
            
            # Lire le fichier original
            with open(original_path, 'rb') as f:
                file_content = f.read()
            
            # Calculer le hash SHA-256
            hash_value = hashlib.sha256(file_content).digest()
            
            # Charger la clé publique du registre
            registry_path = os.path.join(base_dir, "registry.json")
            if not os.path.exists(registry_path):
                return JsonResponse({'error': 'Registre des clés publiques non trouvé'}, status=404)
            
            with open(registry_path, 'r') as f:
                registry = json.load(f)
            
            if username not in registry:
                return JsonResponse({'error': f'Clé publique pour {username} non trouvée dans le registre'}, status=404)
            
            public_key_pem = registry[username]
            
            # Charger la clé publique
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
            
            # Décoder la signature
            signature = base64.b64decode(signature_b64)
            
            # Vérifier la signature
            try:
                public_key.verify(
                    signature,
                    hash_value,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                verification_result = True
                message = "Signature VALIDE"
            except Exception:
                verification_result = False
                message = "Signature INVALIDE"
            
            return JsonResponse({
                'success': True,
                'valid': verification_result,
                'message': message,
                'details': {
                    'user': username,
                    'timestamp': timestamp,
                    'file': original_filename
                }
            })
            
        except Exception as e:
            return JsonResponse({'error': f'Erreur lors de la vérification: {str(e)}'}, status=500)
    
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)
