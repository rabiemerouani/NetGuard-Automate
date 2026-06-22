import os 
def analyze_configuration (device_name, config_text):
    print(f"\n Analyse de seccurité en cours pour : {device_name}: ")
    print("=" * 50)
    vulnerabilities = []
    # Regle 1 : vérifier si Telent est autorisé 
    if "transport input" in config_text:
        for line in config_text.split('\n'):
            if "transport input" in line and "telent" in line:
                vulnerabilities.append({
                                       "severity": "CRITIQUE",
                    "issue": "Protocole non sécurisé (Telnet) activé",
                    "details": f"Ligne détectée : '{line.strip()}'",
                    "fix": "Modifier la configuration pour n'autoriser que SSH : 'transport input ssh'"
                })
    
    # RÈGLE 2 : Vérifier la présence de mots de passe faibles stockés en clair
    if "password" in config_text or "secret 0" in config_text:
        for line in config_text.split('\n'):
            if ("password" in line or "secret 0" in line) and "password123" in line:
                vulnerabilities.append({
                    "severity": "ÉLEVÉE",
                    "issue": "Mot de passe faible ou en clair détecté",
                    "details": f"Ligne détectée : '{line.strip()}'",
                    "fix": "Utiliser un chiffrement fort et changer le mot de passe : 'username <user> secret <strong_password>'"
                })

                # RÈGLE 3 : Vérifier si le serveur HTTP non sécurisé est actif
    if "ip http server" in config_text:
        vulnerabilities.append({
            "severity": "MOYENNE",
            "issue": "Serveur HTTP non chiffré activé",
            "details": "La commande 'ip http server' est présente.",
            "fix": "Désactiver le HTTP obsolète et utiliser HTTPS : 'no ip http server' et 'ip http secure-server'"
        })

        # Affichage du rapport d'audit
    if vulnerabilities:
        print(f" {len(vulnerabilities)} vulnérabilité(s) détectée(s) !")
        for vuln in vulnerabilities:
            print(f"\n[{vuln['severity']}] {vuln['issue']}")
            print(f"   Détails : {vuln['details']}")
            print(f"   Correction : {vuln['fix']}")
    else:
        print("[✔] Félicitations ! Aucune faille de base détectée.")
        
    print("=" * 50)
    return vulnerabilities

if __name__ == "__main__":
    # Test rapide en lisant directement le fichier de simulation du routeur
    sim_path = os.path.join("simulator", "Routeur_Ain_Taya.txt")
    
    if os.path.exists(sim_path):
        with open(sim_path, "r", encoding="utf-8") as f:
            file_content = f.read()
        analyze_configuration("Routeur_Ain_Taya", file_content)
    else:
        print("Impossible de faire le test, le fichier du routeur est introuvable.")