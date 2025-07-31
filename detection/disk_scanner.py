import os
import yara
from datetime import datetime, timezone

def scan_files_with_yara(directories, yara_rules):
    matches = []
    seen_disk = set()
    executable_exts = {'.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.com', '.msi', '.txt'}
    for directory in directories:
        for root, _, files in os.walk(directory):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext not in executable_exts:
                    continue
                try:
                    file_path = os.path.join(root, f)
                    matched = yara_rules.match(filepath=file_path)
                    if matched:
                        dedup_key = (file_path, tuple(sorted(m.rule for m in matched)))
                        if dedup_key in seen_disk:
                            continue
                        seen_disk.add(dedup_key)
                        matches.append({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "source": "disk",
                            "file_path": file_path,
                            "yara_match": [m.rule for m in matched],
                            "severity": "High",  # Default, can be improved
                            "action": "Alerted"
                        })
                except Exception:
                    continue
    return matches 