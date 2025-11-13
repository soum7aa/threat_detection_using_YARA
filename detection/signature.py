# detection/signature.py
try:
    import yara
except Exception:
    yara = None
import os
import re

_STRING_LITERAL_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')

class YaraScanner:
    def __init__(self, rules_dir='yara_rules'):
        self.rules_dir = rules_dir
        self.rules = None  # compiled yara rules when available
        self.fallback_strings = []  # string literals extracted from yara files
        self.reload()

    def reload(self):
        files = []
        if os.path.isdir(self.rules_dir):
            for f in os.listdir(self.rules_dir):
                if f.endswith('.yar') or f.endswith('.yara'):
                    files.append(os.path.join(self.rules_dir, f))

        # Always rebuild fallback string set
        self.fallback_strings = []
        for fp in files:
            try:
                with open(fp, 'r', errors='ignore') as fh:
                    text = fh.read()
                # Collect double-quoted string literals (rough heuristic)
                for m in _STRING_LITERAL_RE.finditer(text):
                    s = m.group(1)
                    if len(s) >= 4:  # ignore very short tokens
                        # unescape common escape sequences
                        s = bytes(s, 'utf-8').decode('unicode_escape', errors='ignore')
                        self.fallback_strings.append(s)
            except Exception:
                continue

        if yara is None or not files:
            self.rules = None
            return bool(self.fallback_strings)

        try:
            self.rules = yara.compile(filepaths={str(i): fp for i, fp in enumerate(files)})
            return True
        except Exception:
            self.rules = None
            return bool(self.fallback_strings)

    def scan_file(self, path):
        if not path or not os.path.exists(path):
            return None

        # Prefer real YARA if available
        if self.rules is not None and yara is not None:
            try:
                matches = self.rules.match(path)
                if matches:
                    out = []
                    for m in matches:
                        out.append(m.rule if hasattr(m, 'rule') else str(m))
                    return out if out else None
            except Exception:
                # fall through to fallback scanning
                pass

        # Fallback: naive string search using extracted literals
        if not self.fallback_strings:
            return None
        try:
            with open(path, 'rb') as fh:
                data = fh.read()
            hits = []
            # Search for a small subset to avoid heavy scans
            check_strings = self.fallback_strings[:200]
            for s in check_strings:
                try:
                    b = s.encode('utf-8', errors='ignore')
                    if b and b in data:
                        hits.append(s[:40])
                        if len(hits) >= 10:
                            break
                except Exception:
                    continue
            return hits if hits else None
        except Exception:
            return None
