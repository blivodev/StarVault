import re
import json
from pathlib import Path

css = Path("lucide.css").read_text(encoding="utf-8")
pat = re.compile(r'\.icon-([a-z0-9-]+):before\s*\{\s*content:\s*"\\([0-9a-f]+)"')
cp = {m.group(1): int(m.group(2), 16) for m in pat.finditer(css)}
print("total lucide icons:", len(cp))

out = Path("starvault/resources/brand/lucide_codepoints.json")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(cp, indent=0, sort_keys=True), encoding="utf-8")
print("written:", out, out.stat().st_size, "bytes")

for name in ["copy", "eye", "eye-off", "pencil", "trash-2", "plus", "x", "check",
             "search", "refresh-cw", "star", "lock", "unlock", "settings", "server",
             "database", "globe", "key", "shield", "fingerprint", "user", "users",
             "tags", "file-key", "shield-check", "activity", "zap", "terminal",
             "chevron-down", "chevron-right", "filter", "download", "upload",
             "maximize-2", "minimize-2", "square-x", "minus", "power", "log-out"]:
    print(f"  {name}: {'OK U+%04X' % cp[name] if name in cp else 'MISSING'}")
