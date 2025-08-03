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
    # Chercher les fichiers .sig disponibles (y compris .mitm_attack.sig)
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    sig_files = []
    
    for file in os.listdir(base_dir):
        if file.endswith('.sig'):
            sig_files.append(file)
    
    # Trier pour mettre les fichiers d'attaque en évidence
    sig_files.sort(key=lambda x: (not x.endswith('.mitm_attack.sig'), x))
    
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
            
            # Trouver le fichier original (gérer les cas .sig et .mitm_attack.sig)
            if sig_filename.endswith('.mitm_attack.sig'):
                original_filename = sig_filename.replace('.mitm_attack.sig', '')
            elif sig_filename.endswith('.sig'):
                original_filename = sig_filename.replace('.sig', '')
            else:
                return JsonResponse({'error': 'Format de fichier de signature non reconnu'}, status=400)
                
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

def mitm_attack_view(request):
    """Affiche la page de simulation d'attaque MITM"""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    
    # Lire le registre actuel
    registry_path = os.path.join(base_dir, "registry.json")
    current_registry = {}
    if os.path.exists(registry_path):
        with open(registry_path, 'r') as f:
            current_registry = json.load(f)
    
    return render(request, 'ca_app/mitm.html', {'current_registry': current_registry})

def simulate_mitm_view(request):
    """Simule une attaque MITM complète en remplaçant une clé publique et signant un document"""
    if request.method == 'POST':
        target_user = request.POST.get('target_user')
        attacker_public_key = request.FILES.get('attacker_public_key')
        attacker_private_key = request.FILES.get('attacker_private_key')
        document_to_sign = request.POST.get('document_to_sign')
        
        if not all([target_user, attacker_public_key, attacker_private_key, document_to_sign]):
            return JsonResponse({'error': 'Tous les champs sont requis pour une attaque complète'}, status=400)
        
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            registry_path = os.path.join(base_dir, "registry.json")
            
            # Lire le registre actuel
            if os.path.exists(registry_path):
                with open(registry_path, 'r') as f:
                    registry = json.load(f)
            else:
                registry = {}
            
            # Sauvegarder l'ancienne clé (pour restauration)
            backup_path = os.path.join(base_dir, "registry_backup.json")
            with open(backup_path, 'w') as f:
                json.dump(registry, f, indent=2)
            
            # ÉTAPE 1: Remplacer la clé publique par celle de l'attaquant
            attacker_key_pem = attacker_public_key.read().decode('utf-8')
            original_key = registry.get(target_user, "Non trouvé")
            registry[target_user] = attacker_key_pem
            
            # Sauvegarder le registre compromis
            with open(registry_path, 'w') as f:
                json.dump(registry, f, indent=2)
            
            # ÉTAPE 2: Signer un document avec la clé privée de l'attaquant
            document_path = os.path.join(base_dir, document_to_sign)
            if not os.path.exists(document_path):
                return JsonResponse({'error': f'Document {document_to_sign} non trouvé'}, status=404)
            
            # Lire le contenu du document
            with open(document_path, 'rb') as f:
                file_content = f.read()
            
            # Calculer le hash SHA-256
            hash_value = hashlib.sha256(file_content).digest()
            
            # Charger la clé privée de l'attaquant
            attacker_private_pem = attacker_private_key.read()
            private_key = serialization.load_pem_private_key(attacker_private_pem, password=None)
            
            # Signer le hash avec la clé privée de l'attaquant
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
            
            # Créer les métadonnées de signature (en se faisant passer pour target_user)
            signature_data = {
                "user": target_user,  # ← L'attaquant se fait passer pour target_user !
                "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "signature": signature_b64
            }
            
            # Sauvegarder dans un fichier .sig avec un nom spécial pour l'attaque
            sig_filename = f"{document_to_sign}.mitm_attack.sig"
            sig_path = os.path.join(base_dir, sig_filename)
            
            with open(sig_path, 'w') as f:
                json.dump(signature_data, f, indent=2)
            
            return JsonResponse({
                'success': True,
                'message': f'🚨 ATTAQUE MITM COMPLÈTE RÉUSSIE !',
                'details': {
                    'target_user': target_user,
                    'original_key_preview': original_key[:50] + "..." if len(original_key) > 50 else original_key,
                    'new_key_preview': attacker_key_pem[:50] + "..." if len(attacker_key_pem) > 50 else attacker_key_pem
                },
                'signature_created': True,
                'signed_file': document_to_sign,
                'signature_file': sig_filename,
                'warning': f'⚠️ L\'attaquant a signé {document_to_sign} en se faisant passer pour {target_user}. Cette signature sera VALIDE car elle utilise les clés correspondantes dans le registre compromis !'
            })
            
        except Exception as e:
            return JsonResponse({'error': f'Erreur lors de la simulation: {str(e)}'}, status=500)
    
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)

def restore_registry_view(request):
    """Restaure le registre original"""
    if request.method == 'POST':
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            registry_path = os.path.join(base_dir, "registry.json")
            backup_path = os.path.join(base_dir, "registry_backup.json")
            
            if os.path.exists(backup_path):
                with open(backup_path, 'r') as f:
                    backup_registry = json.load(f)
                
                with open(registry_path, 'w') as f:
                    json.dump(backup_registry, f, indent=2)
                
                return JsonResponse({
                    'success': True,
                    'message': '✅ Registre restauré avec succès !'
                })
            else:
                return JsonResponse({'error': 'Aucune sauvegarde trouvée'}, status=404)
                
        except Exception as e:
            return JsonResponse({'error': f'Erreur lors de la restauration: {str(e)}'}, status=500)
    
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)

def generate_certificate(username, public_key_pem):
    """Génère un certificat signé par l'Autorité de Certification"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ca_private_path = os.path.join(base_dir, "ca_private.pem")
        
        if not os.path.exists(ca_private_path):
            raise Exception("Clé privée de la CA non trouvée. Exécutez d'abord generate_ca_keys.py")
        
        # Charger la clé privée de la CA
        with open(ca_private_path, 'rb') as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        # Créer le contenu à signer : hash(username + public_key)
        content_to_sign = username + public_key_pem
        content_hash = hashlib.sha256(content_to_sign.encode('utf-8')).digest()
        
        # Signer avec la clé privée de la CA
        ca_signature = ca_private_key.sign(
            content_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Encoder en base64
        ca_signature_b64 = base64.b64encode(ca_signature).decode('utf-8')
        
        # Créer le certificat
        certificate = {
            "username": username,
            "public_key": public_key_pem,
            "CA_signature": ca_signature_b64,
            "issued_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        return certificate
        
    except Exception as e:
        raise Exception(f"Erreur lors de la génération du certificat: {str(e)}")

def verify_certificate(certificate):
    """Vérifie un certificat avec la clé publique de la CA"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ca_public_path = os.path.join(base_dir, "ca_public.pem")
        
        if not os.path.exists(ca_public_path):
            raise Exception("Clé publique de la CA non trouvée")
        
        # Charger la clé publique de la CA
        with open(ca_public_path, 'rb') as f:
            ca_public_key = serialization.load_pem_public_key(f.read())
        
        # Recréer le contenu qui a été signé
        content_to_verify = certificate["username"] + certificate["public_key"]
        content_hash = hashlib.sha256(content_to_verify.encode('utf-8')).digest()
        
        # Décoder la signature
        ca_signature = base64.b64decode(certificate["CA_signature"])
        
        # Vérifier la signature de la CA
        ca_public_key.verify(
            ca_signature,
            content_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return True
        
    except Exception:
        return False

def certificate_upload_view(request):
    """Affiche la page d'upload de certificats"""
    return render(request, 'ca_app/certificate.html')

def register_with_certificate_view(request):
    """Enregistre un utilisateur avec un certificat"""
    if request.method == 'POST':
        certificate_file = request.FILES.get('certificate_file')
        
        if not certificate_file:
            return JsonResponse({'error': 'Fichier de certificat requis'}, status=400)
        
        try:
            # Lire le certificat
            certificate_content = certificate_file.read().decode('utf-8')
            certificate = json.loads(certificate_content)
            
            # Vérifier le certificat
            if not verify_certificate(certificate):
                return JsonResponse({'error': 'Certificat invalide - signature de la CA non vérifiée'}, status=400)
            
            # Enregistrer la clé publique si le certificat est valide
            username = certificate["username"]
            public_key_pem = certificate["public_key"]
            
            register_user(username, public_key_pem)
            
            return JsonResponse({
                'success': True,
                'message': f'✅ Certificat valide ! Utilisateur {username} enregistré avec succès.',
                'details': {
                    'username': username,
                    'issued_at': certificate.get('issued_at', 'Non spécifié')
                }
            })
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Format de certificat invalide'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'Erreur lors du traitement: {str(e)}'}, status=500)
    
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)

def create_certificate_view(request):
    """Crée un nouveau certificat pour un utilisateur"""
    if request.method == 'POST':
        username = request.POST.get('username')
        public_key_file = request.FILES.get('public_key_file')
        
        if not username or not public_key_file:
            return JsonResponse({'error': 'Nom d\'utilisateur et clé publique requis'}, status=400)
        
        try:
            public_key_pem = public_key_file.read().decode('utf-8')
            
            # Générer le certificat
            certificate = generate_certificate(username, public_key_pem)
            
            # Sauvegarder le certificat
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            cert_filename = f"{username}_certificate.json"
            cert_path = os.path.join(base_dir, cert_filename)
            
            with open(cert_path, 'w') as f:
                json.dump(certificate, f, indent=2)
            
            return JsonResponse({
                'success': True,
                'message': f'✅ Certificat créé pour {username} !',
                'certificate_file': cert_filename,
                'certificate': certificate
            })
            
        except Exception as e:
            return JsonResponse({'error': f'Erreur lors de la création: {str(e)}'}, status=500)
    
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)
