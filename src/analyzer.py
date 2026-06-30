import json
import os
import re
import logging
from ciscoconfparse import CiscoConfParse

# Configure the sub-logger for this specific module
logger = logging.getLogger("NetGuard." + __name__)

def load_security_rules():
    """Loads CIS security rules from the JSON configuration file."""
    rules_path = os.path.join("config", "rules.json")
    if os.path.exists(rules_path):
        try:
            with open(rules_path, "r", encoding="utf-8") as file:
                rules = json.load(file)
                logger.debug(f"Successfully loaded {len(rules)} CIS rules from {rules_path}")
                return rules
        except Exception as e:
            logger.error(f"Error reading JSON rules file: {e}")
            return []
    logger.warning(f"Rules configuration file not found at: {rules_path}")
    return []

def search_command_label(parent, child):
    """Cleanly formats the command path display."""
    return f"{parent} -> {child}" if parent else child

def analyze_configuration(device_name, config_text):
    """Analyzes the configuration text using Parent/Child relationships, CIS IDs, and Regex matching."""
    logger.info(f"Starting CIS security compliance audit for device: {device_name}")
    
    parse = CiscoConfParse(config_text.splitlines())
    rules = load_security_rules()
    vulnerabilities = []

    for rule in rules:
        rule_id = rule.get("id", "CIS-UNK")
        parent_cmd = rule.get("parent", "")
        search_cmd = rule["search_command"]
        expected = rule["expected"]
        
        is_vulnerable = False

        # CASE 1: Hierarchical Parent / Child Rules (e.g., line vty)
        if parent_cmd:
            parents = parse.find_objects(f"^{re.escape(parent_cmd)}")
            
            # If we expect the command to be ABSENT
            if expected == "absent":
                for parent in parents:
                    children = parent.re_search_children(f"{search_cmd}")
                    if children:
                        is_vulnerable = True
                        break
            
            # If we expect the command to be PRESENT everywhere
            elif expected == "present":
                if not parents:
                    is_vulnerable = True
                for parent in parents:
                    children = parent.re_search_children(f"{search_cmd}")
                    if not children:
                        is_vulnerable = True

        # CASE 2: Global Commands (e.g., ip http server)
        else:
            found = parse.find_objects(f"^{search_cmd}")
            if expected == "absent" and found:
                is_vulnerable = True
            elif expected == "present" and not found:
                is_vulnerable = True

        # If a vulnerability is matched, append it with standard English metadata properties
        if is_vulnerable:
            logger.warning(f"[{rule_id}] Gap detected on {device_name} -> {rule['name']}")
            vulnerabilities.append({
                "id": rule_id,
                "issue": f"[{rule_id}] {rule['name']}",
                "category": rule.get("category", "General"),
                "level": rule.get("level", 1),
                "severity": rule["severity"],
                "details": f"Violation detected for '{search_command_label(parent_cmd, search_cmd)}'",
                "fix": rule["fix"]
            })

    if vulnerabilities:
        logger.warning(f"Audit complete. {len(vulnerabilities)} CIS vulnerability/vulnerabilities flag(s) identified on {device_name}!")
    else:
        logger.info(f"Audit complete. No CIS compliance deviations detected on {device_name}.")

    return vulnerabilities