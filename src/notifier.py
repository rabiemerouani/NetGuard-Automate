import os
import smtplib
import logging  #  On importe le module de logs
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Charger les variables du fichier .env au démarrage du script
load_dotenv()

#  Configuration du sous-logger pour le module de notification
logger = logging.getLogger("NetGuard." + __name__)

def send_security_alert(device_name, vulnerabilities):
    """Génère et envoie une alerte e-mail basée sur les vulnérabilités trouvées."""
    
    # Récupération des variables depuis le fichier .env
    sender_email = os.getenv("SMTP_SENDER")
    password = os.getenv("SMTP_PASSWORD")
    receiver_email = os.getenv("SMTP_RECEIVER")

    # Vérification de sécurité : si une variable manque dans le .env, on arrête tout
    if not sender_email or not password or not receiver_email:
        logger.error("[SMTP] Configuration SMTP incomplète dans le fichier .env")
        return

    logger.info(f"[SMTP] Préparation de l'envoi de l'alerte pour {device_name}...")
    
    # 1. Création de l'e-mail (Structure de base)
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = f" ALERTE SÉCURITÉ : Faille détectée sur {device_name}"

    # ✍️ 2. Construction du corps du texte de l'e-mail
    body = f"Salut,\n\n"
    body += f"Un audit de sécurité automatique a été effectué sur l'équipement : {device_name}\n"
    body += f"Status : ATTENTION - Des failles de sécurité ont été trouvées.\n"
    body += "============================================================\n\n"

    for vuln in vulnerabilities:
        body += f"[{vuln['severity']}] {vuln['issue']}\n"
        body += f"   Détails : {vuln['details']}\n"
        body += f"   Correction suggérée : {vuln['fix']}\n"
        body += "----------------------------------------\n"

    body += f"\nMerci de traiter ces vulnérabilités dès que possible.\n"
    body += f"Cordialement,\n"
    body += f"Votre robot de supervision NetGuard."

    # Attacher le texte à l'objet e-mail
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    #  3. Connexion au serveur de Google et envoi réel
    try:
        logger.debug("[SMTP] Connexion au serveur smtp.gmail.com sur le port 587...")
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Chiffrement de la connexion
        
        logger.debug("[SMTP] Authentification auprès du serveur Google...")
        server.login(sender_email, password)
        
        logger.info(f"[SMTP] Envoi de l'e-mail d'alerte à {receiver_email}...")
        server.sendmail(sender_email, receiver_email, msg.as_string())
        
        logger.info("[✔] [SMTP] E-mail d'alerte envoyé avec succès !")
        server.quit()
        
    except Exception as e:
        logger.critical(f" [SMTP] Échec de l'envoi de l'e-mail. Erreur : {e}")