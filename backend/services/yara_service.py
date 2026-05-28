import yara
import os
from config import Config

def compile_rules(rules_dir: str = None) -> yara.Rules:
    """Compile all .yar files in the rules directory."""
    if rules_dir is None:
        rules_dir = Config.YARA_RULES_DIR

    rule_files = {}
    for fname in os.listdir(rules_dir):
        if fname.endswith(".yar"):
            namespace = fname.replace(".yar", "")
            rule_files[namespace] = os.path.join(rules_dir, fname)

    if not rule_files:
        raise FileNotFoundError(f"No .yar files found in {rules_dir}")

    return yara.compile(filepaths=rule_files)


def scan_file(file_path: str) -> dict:
    """
    Scan a single file with compiled YARA rules.
    Returns matched rules or 'clean'.
    """
    try:
        rules = compile_rules()
    except Exception as e:
        return {"error": f"Rule compile error: {e}", "file": file_path}

    if not os.path.isfile(file_path):
        return {"error": "File not found", "file": file_path}

    try:
        matches = rules.match(file_path)
    except Exception as e:
        return {"error": str(e), "file": file_path}

    if matches:
        return {
            "file":    file_path,
            "status":  "INFECTED",
            "matches": [{"rule": m.rule, "tags": m.tags, "strings": [
                {"identifier": s.identifier, "offset": s.instances[0].offset}
                for s in m.strings
            ]} for m in matches]
        }

    return {"file": file_path, "status": "clean", "matches": []}


def scan_bytes(data: bytes) -> dict:
    """Scan raw bytes (e.g. uploaded file content)."""
    try:
        rules = compile_rules()
        matches = rules.match(data=data)
    except Exception as e:
        return {"error": str(e)}

    if matches:
        return {
            "status":  "INFECTED",
            "matches": [m.rule for m in matches]
        }
    return {"status": "clean", "matches": []}
