import os
import yara
from datetime import datetime, timezone

def compute_entropy(path, sample_size=8192):
    try:
        import math as _math
        from collections import Counter
        with open(path, 'rb') as f:
            data = f.read(sample_size)
        if not data:
            return 0.0
        counts = Counter(data)
        total = float(len(data))
        entropy = 0.0
        for c in counts.values():
            p = c / total
            entropy -= p * (_math.log(p, 2))
        return entropy
    except Exception:
        return 0.0

def scan_files_with_yara(directories, yara_rules, max_results=None, exclude_rules=None):
    matches = []
    seen_disk = set()
    executable_exts = {'.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.com', '.msi', '.txt', '.bin'}
    excluded = set(exclude_rules or [])
    for directory in directories:
        for root, _, files in os.walk(directory):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext not in executable_exts:
                    continue
                try:
                    file_path = os.path.join(root, f)
                    matched = yara_rules.match(filepath=file_path)
                    # Fallback: some environments may fail filepath-based matching for temp files
                    if not matched:
                        try:
                            with open(file_path, 'rb') as _fb:
                                _data = _fb.read()
                            if _data:
                                matched = yara_rules.match(data=_data)
                        except Exception:
                            matched = []
                    if matched:
                        # Filter excluded rules
                        matched = [m for m in matched if m.rule not in excluded]
                        if not matched:
                            continue
                        dedup_key = (file_path, tuple(sorted(m.rule for m in matched)))
                        if dedup_key in seen_disk:
                            continue
                        seen_disk.add(dedup_key)
                        # Aggregate metadata and compute severity
                        details = []
                        severities = []
                        for m in matched:
                            meta = getattr(m, 'meta', {}) or {}
                            # Safely convert matched strings to text without raising
                            safe_strings = []
                            try:
                                for s in getattr(m, 'strings', []):
                                    try:
                                        val = s[2] if len(s) > 2 else b""
                                        if isinstance(val, (bytes, bytearray)):
                                            safe_strings.append(val.decode('latin-1', errors='ignore'))
                                        else:
                                            safe_strings.append(str(val))
                                    except Exception:
                                        try:
                                            safe_strings.append(repr(s))
                                        except Exception:
                                            safe_strings.append("<unprintable>")
                            except Exception:
                                safe_strings = []

                            details.append({
                                "rule": m.rule,
                                "meta": meta,
                                "strings": safe_strings
                            })
                            sev = (meta.get('severity') or '').title()
                            if sev in ["Low", "Medium", "High", "Critical"]:
                                severities.append(sev)

                        rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
                        severity = "Medium"
                        if severities:
                            severity = max(severities, key=lambda s: rank.get(s, 1))

                        # Optional entropy check for non-PE blobs
                        entropy = compute_entropy(file_path, 8192)
                        matches.append({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "source": "disk",
                            "file_path": file_path,
                            "yara_match": [m.rule for m in matched],
                            "yara_details": details,
                            "severity": severity,
                            "action": "Alerted",
                            "file_entropy": round(entropy, 3)
                        })
                        if max_results is not None and len(matches) >= max_results:
                            return matches
                except Exception:
                    continue
    return matches 