#!/usr/bin/env python3
"""Keeps DayBookEvtxMacOS/Localizable.xcstrings in sync with the code and reports gaps.

usage: scripts/sync_strings.py [--derived-data DIR]

1. Builds the app (xcodebuild, Release) — the compiler writes .stringsdata for the app target.
2. Builds DaybookKit from scratch with -emit-localized-strings: messages produced inside the
   package (DQL errors, event descriptions, Sigma reasons) are looked up in the app's catalog,
   because String(localized:) without a bundle uses the main bundle.
3. Runs `xcstringstool sync` with both sets, marks keys without Cyrillic as not translatable,
   and lists keys that still lack an English translation (exit code 1 if any).
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "DayBookEvtxMacOS", "Localizable.xcstrings")
ENV = dict(os.environ, DEVELOPER_DIR=os.environ.get("DEVELOPER_DIR", "/Applications/Xcode.app/Contents/Developer"))


def run(args, cwd=ROOT):
    r = subprocess.run(args, cwd=cwd, env=ENV, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout[-2000:] + r.stderr[-2000:])
        sys.exit(f"failed: {' '.join(args[:3])}…")
    return r


def main():
    derived = sys.argv[sys.argv.index("--derived-data") + 1] if "--derived-data" in sys.argv else tempfile.mkdtemp(prefix="daybook-dd-")
    run(["xcodebuild", "-project", "DayBookEvtxMacOS.xcodeproj", "-scheme", "DayBookEvtxMacOS",
         "-configuration", "Release", "-derivedDataPath", derived, "build"])
    app_sd = glob.glob(os.path.join(derived, "Build/Intermediates.noindex/DayBookEvtxMacOS.build/Release/"
                                    "DayBookEvtxMacOS.build/Objects-normal/*/*.stringsdata"))

    pkg_build = tempfile.mkdtemp(prefix="daybook-loc-build-")
    pkg_out = tempfile.mkdtemp(prefix="daybook-loc-")
    try:
        run(["swift", "build", "-c", "release", "--build-path", pkg_build,
             "-Xswiftc", "-emit-localized-strings", "-Xswiftc", "-emit-localized-strings-path", "-Xswiftc", pkg_out],
            cwd=os.path.join(ROOT, "Packages", "DaybookKit"))
        files = app_sd + glob.glob(os.path.join(pkg_out, "*.stringsdata"))
        ours = [f for f in files if json.load(open(f)).get("source", "").startswith(ROOT)
                and "/.build/" not in json.load(open(f)).get("source", "")]
        args = ["xcrun", "xcstringstool", "sync", CATALOG]
        for f in ours:
            args += ["--stringsdata", f]
        run(args)
    finally:
        shutil.rmtree(pkg_build, ignore_errors=True)
        shutil.rmtree(pkg_out, ignore_errors=True)

    doc = json.load(open(CATALOG, encoding="utf-8"))
    cyr = re.compile(r"[А-Яа-яЁё]")
    missing = []
    for key, entry in doc["strings"].items():
        if not cyr.search(key):
            entry["shouldTranslate"] = False
            continue
        if entry.get("localizations", {}).get("en", {}).get("stringUnit", {}).get("value") is None:
            missing.append(key)
    with open(CATALOG, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"{len(doc['strings'])} keys, {len(missing)} without English")
    for k in missing:
        print("  ", json.dumps(k, ensure_ascii=False))
    sys.exit(1 if missing else 0)


if __name__ == "__main__":
    main()
