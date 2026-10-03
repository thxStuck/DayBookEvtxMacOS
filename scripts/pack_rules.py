#!/usr/bin/env python3
"""Packs Windows detection rules into the app resource DayBookEvtxMacOS/Resources/Rules/rules.json.

usage: pack_rules.py <unzipped sigma_all_rules> <unzipped hayabusa-rules-main> [out.json]

Sources (both under the Detection Rule License 1.1, which requires keeping each rule's
author attribution — the app shows it next to every detection):
  * SigmaHQ release package (rules/windows/** and Windows rules from rules-emerging-threats/**)
  * Hayabusa's own rules (hayabusa/**); its sigma/ folder is a converted copy of SigmaHQ and is skipped.
Every rule keeps its original YAML text and repository path.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone


def collect(root, pick):
    out = []
    for dirpath, _, files in os.walk(root):
        for f in sorted(files):
            if not f.endswith((".yml", ".yaml")):
                continue
            full = os.path.join(dirpath, f)
            rel = os.path.relpath(full, root)
            with open(full, encoding="utf-8") as fh:
                text = fh.read()
            if pick(rel, text):
                out.append((rel, text))
    return sorted(out)


def windows(rel, text):
    if rel.startswith("rules/windows/"):
        return True
    return bool(re.search(r"^\s*product:\s*windows\s*$", text, re.M))


def main():
    sigma_root, hayabusa_root = sys.argv[1], sys.argv[2]
    out_path = sys.argv[3] if len(sys.argv) > 3 else os.path.join(
        os.path.dirname(__file__), "..", "DayBookEvtxMacOS", "Resources", "Rules", "rules.json")
    version = "?"
    vfile = os.path.join(sigma_root, "version.txt")
    if os.path.exists(vfile):
        with open(vfile, encoding="utf-8") as fh:
            version = " · ".join(line.strip() for line in fh if line.strip())

    sigma = collect(sigma_root, lambda rel, text: rel.startswith(("rules/", "rules-emerging-threats/")) and windows(rel, text))
    hayabusa = collect(os.path.join(hayabusa_root, "hayabusa"), lambda rel, text: True)

    # Hayabusa rules use field aliases (e.g. LogFileClearedChannel -> Event.UserData.LogFileCleared.Channel).
    aliases = {}
    with open(os.path.join(hayabusa_root, "config", "eventkey_alias.txt"), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "," not in line:
                continue
            alias, path = line.split(",", 1)
            if alias != "alias":
                aliases[alias.strip()] = path.strip()

    rules = [{"source": "SigmaHQ", "path": rel, "yaml": text} for rel, text in sigma]
    rules += [{"source": "Hayabusa", "path": "hayabusa/" + rel, "yaml": text} for rel, text in hayabusa]
    doc = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": [
            {"name": "SigmaHQ", "url": "https://github.com/SigmaHQ/sigma", "version": version,
             "license": "Detection Rule License (DRL) 1.1", "licenseURL": "https://github.com/SigmaHQ/Detection-Rule-License",
             "count": len(sigma)},
            {"name": "Hayabusa", "url": "https://github.com/Yamato-Security/hayabusa-rules", "version": "main",
             "license": "Detection Rule License (DRL) 1.1", "licenseURL": "https://github.com/Yamato-Security/hayabusa-rules/blob/main/LICENSE.md",
             "count": len(hayabusa)},
        ],
        "aliases": aliases,
        "aliasesSource": "Hayabusa config/eventkey_alias.txt (DRL 1.1)",
        "rules": rules,
    }
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, separators=(",", ":"))
    print(f"{out_path}: SigmaHQ {len(sigma)}, Hayabusa {len(hayabusa)} rules, {len(aliases)} aliases, {os.path.getsize(out_path) / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
