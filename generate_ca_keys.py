#!/usr/bin/env python3
"""
Génération des clés RSA pour l'Autorité de Certification (CA)
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_ca_keys():
    """Génère une paire de clés RSA pour l'Autorité de Certification"""
    
    # Générer la clé privée
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Extraire la clé publique
    public_key = private_key.public_key()
    
    # Sérialiser la clé privée en format PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Sérialiser la clé publique en format PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Sauvegarder les clés
    with open("ca_private.pem", "wb") as f:
        f.write(private_pem)
    
    with open("ca_public.pem", "wb") as f:
        f.write(public_pem)
    
    print("✅ Clés de l'Autorité de Certification générées :")
    print("   - ca_private.pem (clé privée de la CA)")
    print("   - ca_public.pem (clé publique de la CA)")

if __name__ == "__main__":
    generate_ca_keys()
