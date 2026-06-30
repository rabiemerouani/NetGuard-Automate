import json
import os
import re
import logging  # On importe le module de logs
from ciscoconfparse import CiscoConfParse

# Configuration du sous-logger pour ce module spécifique
logger = logging.getLogger("NetGuard." + __name__)

def load_security_rules():
    """Charge les règles de sécurité CIS depuis le fichier JSON."""
    rules_path = os.path.join("config", "rules.json")
    if os.path.exists(rules_path):
        try:
            with open(rules_path, "r", encoding="utf-8") as file:
                rules = json.load(file)
                logger.debug(f"Chargement réussi de {len(rules)} règles CIS depuis {rules_path}")
                return rules
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du fichier de règles JSON : {e}")
            return []
    logger.warning(f"Le fichier de règles est introuvable au chemin : {rules_path}")
    return []

def search_command_label(parent, child):
    """Formate proprement l'affichage du chemin de la commande."""
    return f"{parent} -> {child}" if parent else child

def analyze_configuration(device_name, config_text):
    """Analyse la configuration avec support Parent/Enfant, ID CIS et Regex."""
    logger.info(f"Analyse de sécurité CIS en cours pour l'équipement : {device_name}")
    
    parse = CiscoConfParse(config_text.splitlines())
    rules = load_security_rules()
    vulnerabilities = []

    for rule in rules:
        rule_id = rule.get("id", "CIS-UNK")
        parent_cmd = rule.get("parent", "")
        search_cmd = rule["search_command"]
        expected = rule["expected"]
        
        is_vulnerable = False

        # CAS 1 : Règle hiérarchique Parent / Enfant (Ex: line vty)
        if parent_cmd:
            # Le parent reste échappé car c'est une commande fixe (ex: ^line vty)
            parents = parse.find_objects(f"^{re.escape(parent_cmd)}")
            
            # Si on attend que la commande soit ABSENTE (ex: transport input telnet)
            if expected == "absent":
                for parent in parents:
                    #  Pas de re.escape ici pour permettre l'évaluation de la regex du JSON
                    children = parent.re_search_children(f"{search_cmd}")
                    if children:
                        is_vulnerable = True
                        break
            
            # Si on attend que la commande soit PRÉSENTE partout (ex: un timeout obligatoire)
            elif expected == "present":
                if not parents:
                    is_vulnerable = True
                for parent in parents:
                    #  Pas de re.escape ici non plus
                    children = parent.re_search_children(f"{search_cmd}")
                    if not children:
                        is_vulnerable = True

        # CAS 2 : Commande globale (Ex: ip http server)
        else:
            #  On retire re.escape pour que "ip ssh version 1" ou d'autres regex fonctionnent globalement
            found = parse.find_objects(f"^{search_cmd}")
            if expected == "absent" and found:
                is_vulnerable = True
            elif expected == "present" and not found:
                is_vulnerable = True

        # Si une vulnérabilité est détectée, on l'ajoute avec ses métadonnées d'expert
        if is_vulnerable:
            logger.warning(f"[{rule_id}] Faille détectée sur {device_name} -> {rule['name']}")
            vulnerabilities.append({
                "id": rule_id,
                "issue": f"[{rule_id}] {rule['name']}",
                "category": rule.get("category", "Général"),  #  Ajout de la catégorie
                "level": rule.get("level", 1),                #  Ajout du niveau CIS (1 ou 2)
                "severity": rule["severity"],
                "details": f"Violation détectée pour '{search_command_label(parent_cmd, search_cmd)}'",
                "fix": rule["fix"]
            })

    #  Correction du niveau de log : WARNING au lieu d'ERROR pour un résultat d'audit normal avec failles
    if vulnerabilities:
        logger.warning(f"Analyse terminée. {len(vulnerabilities)} vulnérabilité(s) CIS détectée(s) sur {device_name} !")
    else:
        logger.info(f"Analyse terminée. Aucun écart de conformité CIS détecté sur {device_name}.")

    return vulnerabilities