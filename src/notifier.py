import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Charger les variables du fichier .env au démarrage du script
load_dotenv()

def send_security_alert(device_name, vulnerabilities):
    """Génère et envoie une alerte e-mail basée sur les vulnérabilités trouvées."""
    
    # 🛠️ Récupération des variables depuis le fichier .env
    sender_email = os.getenv("SMTP_SENDER")
    password = os.getenv("SMTP_PASSWORD")
    receiver_email = os.getenv("SMTP_RECEIVER")

    # Vérification de sécurité : si une variable manque dans le .env, on arrête tout
    if not sender_email or not password or not receiver_email:
        print(" [SMTP] Erreur : Configuration SMTP incomplète dans le fichier .env")
        return

    print(f"[SMTP] Connexion au serveur smtp.gmail.com...")
    
    #  1. Création de l'e-mail (Structure de base)
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

    # 3. Connexion au serveur de Google et envoi réel
    try:
        # Connexion sur le port sécurisé TLS (587)
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Chiffrement de la connexion
        
        print("[SMTP] Authentification sécurisée...")
        server.login(sender_email, password)
        
        print(f"[SMTP] Envoi de l'alerte à {receiver_email}...")
        server.sendmail(sender_email, receiver_email, msg.as_string())
        
        print(" [SMTP] E-mail d'alerte envoyé avec succès !")
        server.quit()
        
    except Exception as e:
        print(f"[SMTP] Échec de l'envoi de l'e-mail. Erreur : {e}")