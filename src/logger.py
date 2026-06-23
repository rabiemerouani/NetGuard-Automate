import logging
import os

def setup_logger():
    """Configure et retourne le logger principal de l'application NetGuard."""
    logger = logging.getLogger("NetGuard")
    
    #  Protection : Si le logger a déjà été configuré, on ne fait rien
    if logger.handlers:
        return logger

    # Empêcher la duplication des logs vers le root logger
    logger.propagate = False

    # Déterminer le niveau de log depuis le .env (Fallback sur INFO si absent)
    log_level_str = os.getenv("NETGUARD_LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_str, logging.INFO)
    logger.setLevel(log_level)

    # Création du dossier de logs s'il n'existe pas
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, "netguard.log")
    
    # Format standardisé pour les professionnels
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] [%(name)s] %(message)s")

    # Handler 1 : Écriture dans le fichier
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Handler 2 : Affichage dans le terminal
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger