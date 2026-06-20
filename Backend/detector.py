import json
import re
from pathlib import Path
from urllib.parse import unquote_plus


SIGNATURES_FILE = Path(__file__).with_name("signatures.json")


def load_signatures():
    with open(SIGNATURES_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def get_path_versions(path):
    decoded_once = unquote_plus(path)
    decoded_twice = unquote_plus(decoded_once)

    return [
        path,
        decoded_once,
        decoded_twice
    ]


SIGNATURES = load_signatures()


def detect_attack(path):
    path_versions = get_path_versions(path)

    for attack_name, attack_data in SIGNATURES.items():
        severity = attack_data["severity"]
        patterns = attack_data["patterns"]

        for pattern in patterns:
            for version in path_versions:
                found = re.search(pattern, version, re.IGNORECASE)

                if found:
                    return {
                        "attack_type": attack_name,
                        "severity": severity
                    }

    return {
        "attack_type": "NORMAL",
        "severity": "LOW"
    }
