import logging
from src.logger import setup_logger  # 👈 On initialise le système de logs
from src.collector import load_devices, get_device_configuration
from src.analyzer import analyze_configuration
from src.notifier import send_security_alert

# Initialisation globale du logger au démarrage de l'application
logger = setup_logger()

def run_netguard():
    logger.info("==================================================")
    logger.info("[       LANCEMENT DE L'AUDIT AUTOMATISÉ          ]")
    logger.info("==================================================")
    
    devices = load_devices()
    if not devices:
        logger.warning("Fin du programme : aucun équipement trouvé à auditer.")
        return

    logger.info(f"{len(devices)} équipement(s) détecté(s) dans la base.")

    for device in devices:
        name = device["device_name"]
        ip = device["ip_address"]
        
        logger.info(f"Début de la session d'audit pour l'équipement : {name} ({ip})")
        
        # 1. Étape de collecte
        config_text = get_device_configuration(name, ip)
        
        # 2. Étape d'analyse
        if config_text:
            vulnerabilities = analyze_configuration(name, config_text)
            
            # 3. Étape d'alerte
            if vulnerabilities:
                logger.info(f"Envoi de la notification par e-mail pour {name}...")
                send_security_alert(name, vulnerabilities)
            else:
                logger.info(f"Aucun écart détecté. Envoi d'alerte inutile pour {name}.")
                
        else:
            logger.error(f"Impossible d'analyser {name} : Échec critique de la collecte de configuration.")
            
    logger.info("==================================================")
    logger.info("[             FIN DE LA SESSION D'AUDIT          ]")
    logger.info("==================================================")

if __name__ == "__main__":
    run_netguard()