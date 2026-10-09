# python3 secretscan.py file.txt
# python3 secretscan.py target.js
#!/usr/bin/env python3

import re
import sys
from pathlib import Path

PATTERNS = {
    "AWS access key ID": r"\bAKIA[0-9A-Z]{16}\b",
    "GitHub token": r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
    "Private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "JWT-like token": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "Possible secret assignment": (
        r"""(?i)\b(?:api[_-]?key|client[_-]?secret|"""
        r"""access[_-]?token|auth[_-]?token|"""
        r"""secret[_-]?key|password)\b"""
        r"""\s*[:=]\s*["']([^"' \r\n]{8,})["']"""
    ),
    "Email address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
}

TEXT_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".html", ".json",
    ".txt", ".env", ".yaml", ".yml", ".xml",
    ".ts", ".config", ".properties"
}

def redact(value):
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]

def scan_file(path):
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0

    findings = 0

    for label, pattern in PATTERNS.items():
        for match in re.finditer(pattern, content):
            value = match.group(1) if match.lastindex else match.group(0)
            line = content.count("\n", 0, match.start()) + 1

            print(
                f"[{label}] {path}:{line} "
                f"value={redact(value)}"
            )
            findings += 1

    return findings

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {Path(sys.argv[0]).name} <file-or-directory>")
        sys.exit(1)

    target = Path(sys.argv[1])

    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = [
            p for p in target.rglob("*")
            if p.is_file() and p.suffix.lower() in TEXT_EXTENSIONS
        ]
    else:
        print("Error: path does not exist.")
        sys.exit(1)

    total = sum(scan_file(path) for path in files)
    print(f"\nFiles scanned: {len(files)}")
    print(f"Potential findings: {total}")
    print("Review findings manually; matches are not proof of exposure.")

if __name__ == "__main__":
    main()
