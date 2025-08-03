from django import forms

class PublicKeyUploadForm(forms.Form):
    username = forms.CharField(label='Nom d’utilisateur')
    public_key_file = forms.FileField(label='Clé publique (.pem)')
