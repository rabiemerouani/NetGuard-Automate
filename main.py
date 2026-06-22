from src.collector import load_devices, get_device_configuration
from src.analyzer import analyze_configuration

def run_netguard():
    print("[==================================================]")
    print("[       LANCEMENT DE L'AUDIT AUTOMATISÉ            ]")
    print("[==================================================]")
    
    # 1. On charge les équipements depuis config/devices.json
    devices = load_devices()
    if not devices:
        print("Fin du programme : aucun équipement à auditer.")
        return

    # 2. On boucle sur chaque équipement de la liste
    for device in devices:
        name = device["device_name"]
        ip = device["ip_address"]
        
        # ÉTAPE A : Le Collector récupère la configuration via SSH
        config_text = get_device_configuration(name, ip)
        
        # ÉTAPE B : Si la collecte a réussi, l'Analyseur prend le relais immédiatement
        if config_text:
            analyze_configuration(name, config_text)
        else:
            print(f"Impossible d'analyser {name} (Échec de la collecte).")

if __name__ == "__main__":
    run_netguard()