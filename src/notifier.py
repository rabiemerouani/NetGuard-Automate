import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_security_alert(device_name, vulnerabilities):
    """Envoie un rapport d'audit par e-mail si des failles sont détectées."""
    
    # 1. Configuration du serveur SMTP (Exemple avec Gmail)
    #  Pour tester, il faudra remplacer par tes vraies informations ou un serveur de test
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SENDER_EMAIL = "merouani1706@gmail.com"
    SENDER_PASSWORD = "zwyo ybbd bzwn icrn"  # Ce n'est pas ton vrai mot de passe, mais un jeton généré par Google
    RECEIVER_EMAIL = "merouani1706@gmail.com"

    # 2. Construction du corps du mail en fonction des failles
    subject = f"[NetGuard Alerte] Vulnérabilités critiques détectées sur {device_name}"
    
    body = f"Bonjour de NetGuard-Automate,\n\n"
    body += f"Un audit de sécurité automatique a été effectué sur l'équipement : {device_name}\n"
    body += f"Status : ATTENTION - Des failles de sécurité ont été trouvées.\n"
    body += "=" * 60 + "\n\n"

    for vuln in vulnerabilities:
        body += f"[{vuln['severity']}] {vuln['issue']}\n"
        body += f"   Détails : {vuln['details']}\n"
        body += f"   Correction suggérée : {vuln['fix']}\n"
        body += "-" * 40 + "\n"

    body += "\nMerci de traiter ces vulnérabilités dès que possible.\n"
    body += "Cordialement,\nVotre robot de supervision NetGuard."

    # 3. Création de l'objet Message (Format MIME standard)
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    # 4. Connexion au serveur et envoi de l'e-mail
    try:
        print(f"[SMTP] Connexion au serveur {SMTP_SERVER}...")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # Sécurise la connexion avec TLS (Chiffrement)
        
        print("[SMTP] Authentification...")
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        
        print(f"[SMTP] Envoi de l'alerte à {RECEIVER_EMAIL}...")
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        
        print("[✔] [SMTP] E-mail d'alerte envoyé avec succès !")
        server.quit()
        
    except Exception as e:
        print(f"Erreur SMTP : Impossible d'envoyer l'e-mail. Détails : {e}")