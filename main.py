from src.collector import load_devices, get_device_configuration
from src.analyzer import analyze_configuration
from src.notifier import send_security_alert  # On importe le notificateur SMTP

def run_netguard():
    print("[==================================================]")
    print("[       LANCEMENT DE L'AUDIT AUTOMATISÉ            ]")
    print("[==================================================]")
    
    devices = load_devices()
    if not devices:
        print("Fin du programme : aucun équipement à auditer.")
        return

    for device in devices:
        name = device["device_name"]
        ip = device["ip_address"]
        
        # 1. Étape de collecte
        config_text = get_device_configuration(name, ip)
        
        # 2. Étape d'analyse
        if config_text:
            # ⚠️ Attention à bien stocker le résultat dans "vulnerabilities" au pluriel et en anglais
            vulnerabilities = analyze_configuration(name, config_text)
            
            # 3. Étape d'alerte (Phase 3)
            if vulnerabilities:
                send_security_alert(name, vulnerabilities)
            else:
                print(f"Aucun besoin d'envoyer d'alerte pour {name}.")
                
        else:
            print(f" Impossible d'analyser {name} (Échec de la collecte).")

if __name__ == "__main__":
    run_netguard()