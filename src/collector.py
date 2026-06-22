import os
import json
import time

def load_devices():
    """Charge la liste des équipements depuis le fichier de configuration JSON."""
    config_path = os.path.join("config", "devices.json")
    if not os.path.exists(config_path):
        print("Erreur : Le fichier config/devices.json est introuvable.")
        return []
    with open(config_path, "r", encoding="utf-8") as file:
        return json.load(file)

def get_device_configuration(device_name, ip_address):
    """Simule une connexion SSH pour récupérer la configuration d'un équipement."""
    print(f"\n [SSH] Tentative de connexion à {device_name} ({ip_address})...")
    time.sleep(0.5)  # Simule la latence réseau
    
    # Chemin vers le fichier de simulation du routeur
    file_path = os.path.join("simulator", f"{device_name}.txt")
    
    if os.path.exists(file_path):
        print(f" Connexion SSH réussie à {device_name} !")
        print("-" * 50)
        with open(file_path, "r", encoding="utf-8") as file:
            config_data = file.read()
            print(config_data)
        print("-" * 50)
        return config_data
    else:
        print(f" Erreur SSH : Impossible de joindre l'équipement {device_name}.")
        return None

if __name__ == "__main__":
    print("[=== DÉMARRAGE DU COLLECTOR NETGUARD ===]")
    # 1. Charger les équipements
    devices = load_devices()
    
    # 2. Lancer la collecte pour le premier équipement (Ton routeur d'Ain Taya)
    if devices:
        first_device = devices[0]
        get_device_configuration(first_device["device_name"], first_device["ip_address"])
    else:
        print("Aucun équipement trouvé dans la configuration.")