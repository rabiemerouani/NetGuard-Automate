import os
import json
import time
import logging  # 👈 On importe le module de logs

# 🛠️ Configuration du sous-logger pour le module de collecte
logger = logging.getLogger("NetGuard." + __name__)

def load_devices():
    """Charge la liste des équipements depuis le fichier de configuration JSON."""
    config_path = os.path.join("config", "devices.json")
    if not os.path.exists(config_path):
        logger.error(f"Le fichier de configuration est introuvable au chemin : {config_path}")
        return []
    
    try:
        with open(config_path, "r", encoding="utf-8") as file:
            devices = json.load(file)
            logger.debug(f"Chargement réussi de {len(devices)} équipement(s) depuis {config_path}")
            return devices
    except Exception as e:
        logger.error(f"Erreur lors de la lecture du fichier de périphériques JSON : {e}")
        return []

def get_device_configuration(device_name, ip_address):
    """Simule une connexion SSH pour récupérer la configuration d'un équipement."""
    logger.info(f"[SSH] Tentative de connexion à {device_name} ({ip_address})...")
    time.sleep(0.5)  # Simule la latence réseau
    
    # Chemin vers le fichier de simulation du routeur
    file_path = os.path.join("simulator", f"{device_name}.txt")
    
    if os.path.exists(file_path):
        logger.info(f"[SSH] Connexion réseau établie avec succès à {device_name} !")
        
        with open(file_path, "r", encoding="utf-8") as file:
            config_data = file.read()
            # On loggue la configuration collectée en niveau DEBUG pour ne pas surcharger le terminal en production
            logger.debug(f"Configuration brute collectée pour {device_name} :\n{config_data}")
            return config_data
    else:
        logger.error(f"[SSH] Échec de la connexion : Impossible de joindre l'équipement {device_name}.")
        return None

if __name__ == "__main__":
    # Ce bloc ne s'exécute que si tu lances directement collector.py
    from src.logger import setup_logger
    setup_logger()
    
    logger.info("[=== DÉMARRAGE DU COLLECTOR NETGUARD (TEST) ===]")
    devices = load_devices()
    if devices:
        get_device_configuration(devices[0]["device_name"], devices[0]["ip_address"])
    else:
        logger.warning("Aucun équipement trouvé dans la configuration.")