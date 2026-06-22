import json
import os
import re
from ciscoconfparse import CiscoConfParse

def load_security_rules():
    """Charge les règles de sécurité CIS depuis le fichier JSON."""
    rules_path = os.path.join("config", "rules.json")
    if os.path.exists(rules_path):
        with open(rules_path, "r", encoding="utf-8") as file:
            return json.load(file)
    return []

def search_command_label(parent, child):
    """Formate proprement l'affichage du chemin de la commande."""
    return f"{parent} -> {child}" if parent else child

def analyze_configuration(device_name, config_text):
    """Analyse la configuration avec support Parent/Enfant et ID CIS."""
    print(f"\nAnalyse de sécurité CIS en cours pour : {device_name}...")
    
    parse = CiscoConfParse(config_text.splitlines())
    rules = load_security_rules()
    vulnerabilities = []

    for rule in rules:
        rule_id = rule.get("id", "CIS-UNK")  #  On récupère l'ID (ex: CIS-3.1)
        parent_cmd = rule.get("parent", "")
        search_cmd = rule["search_command"]
        expected = rule["expected"]
        
        is_vulnerable = False

        # CAS 1 : Règle hiérarchique Parent / Enfant (Ex: line vty)
        if parent_cmd:
            parents = parse.find_objects(f"^{re.escape(parent_cmd)}")
            
            # Si on attend que la commande soit ABSENTE (ex: telnet)
            if expected == "absent":
                for parent in parents:
                    children = parent.re_search_children(f"{re.escape(search_cmd)}")
                    if children:
                        is_vulnerable = True
                        break  # Une seule preuve suffit à déclarer le device vulnérable
            
            # Si on attend que la commande soit PRÉSENTE partout (ex: un timeout obligatoire)
            elif expected == "present":
                if not parents:
                    is_vulnerable = True  # Le bloc parent lui-même n'existe pas !
                for parent in parents:
                    children = parent.re_search_children(f"{re.escape(search_cmd)}")
                    if not children:
                        is_vulnerable = True  # Un des blocs parent n'est pas sécurisé

        # CAS 2 : Commande globale (Ex: ip http server)
        else:
            found = parse.find_objects(f"^{re.escape(search_cmd)}")
            if expected == "absent" and found:
                is_vulnerable = True
            elif expected == "present" and not found:
                is_vulnerable = True

        # Si une vulnérabilité est détectée, on l'ajoute avec son ID
        if is_vulnerable:
            vulnerabilities.append({
                "id": rule_id,  # 👈 Ajout de l'ID dans le dictionnaire final
                "issue": f"[{rule_id}] {rule['name']}",  # Plus lisible dans l'e-mail
                "severity": rule["severity"],
                "details": f"Violation détectée pour '{search_command_label(parent_cmd, search_cmd)}'",
                "fix": rule["fix"]
            })

    # Affichage terminal
    print("=" * 60)
    print(f"  {len(vulnerabilities)} vulnérabilité(s) CIS détectée(s) !")
    for v in vulnerabilities:
        print(f"[{v['severity']}] {v['issue']}")
    print("=" * 60)

    return vulnerabilities