import json
from django.shortcuts import render
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
