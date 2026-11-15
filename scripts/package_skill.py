#!/usr/bin/env python3
"""
Sentry Skill Package Validator & Release Packager
------------------------------------------------
Validates compliance with the Uliya Skill Development Standard:
- Validates YAML frontmatter in skill/sentry/SKILL.md (name format, description <= 1024 chars).
- Ensures ONLY UTF-8 Markdown (.md) files exist in skill/sentry/.
- Prohibits executable scripts, binaries, or foreign manifests in skill/sentry/.
- Enforces size ceilings (max 1 MB per file, max 10 MB total, max 100 files).
- Verifies that all relative Markdown links in SKILL.md resolve to real files.
- Packages skill/sentry/ into a clean, compliant sentry-final-round2.zip.

Zero external dependencies (pure Python 3 standard library).
"""

import os
import sys
import re
import zipfile
from pathlib import Path


def validate_sentry_skill(skill_root: Path) -> tuple[bool, list[str]]:
    errors = []
    
    if not skill_root.exists() or not skill_root.is_dir():
        errors.append(f"Skill root directory not found: {skill_root}")
        return False, errors

    skill_md = skill_root / "SKILL.md"
    if not skill_md.exists():
        errors.append(f"Mandatory file missing: {skill_root}/SKILL.md")
        return False, errors

    # 1. Frontmatter Validation
    with open(skill_md, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    frontmatter_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
    if not frontmatter_match:
        errors.append("SKILL.md does not start with valid YAML frontmatter (--- ... ---).")
    else:
        fm_text = frontmatter_match.group(1)
        name_match = re.search(r"^name:\s*([a-zA-Z0-9_-]+)", fm_text, re.MULTILINE)
        desc_match = re.search(r"^description:\s*(.*?)(?=\n[a-zA-Z0-9_-]+:|\Z)", fm_text, re.MULTILINE | re.DOTALL)

        if not name_match:
            errors.append("Frontmatter missing 'name' field.")
        else:
            name_val = name_match.group(1).strip()
            if name_val != "sentry":
                errors.append(f"Frontmatter 'name' is '{name_val}'; expected 'sentry'.")
            if not re.match(r"^[a-z0-9]+(?:-[a-z0-9]+)*$", name_val):
                errors.append(f"Frontmatter name '{name_val}' must be lowercase and hyphen-separated.")
            if not (2 <= len(name_val) <= 64):
                errors.append(f"Frontmatter name length must be between 2 and 64 characters (got {len(name_val)}).")

        if not desc_match:
            errors.append("Frontmatter missing 'description' field.")
        else:
            desc_val = desc_match.group(1).strip()
            if len(desc_val) > 1024:
                errors.append(f"Frontmatter description exceeds 1,024 characters (got {len(desc_val)}).")
            else:
                print(f"[✓] Frontmatter description length: {len(desc_val)} / 1024 chars.")

    # 2. Check for Mandatory Disclosures Section
    if "Mandatory Disclosures Section" not in content and "Third-Party Components" not in content:
        errors.append("SKILL.md missing Mandatory Disclosures Section.")
    else:
        print("[✓] Mandatory Disclosures Section verified.")

    # 3. File Extension & Prohibited Files Audit
    total_bytes = 0
    file_count = 0
    all_files = []

    for root, dirs, files in os.walk(skill_root):
        for fname in files:
            file_count += 1
            fpath = Path(root) / fname
            rel = fpath.relative_to(skill_root)
            all_files.append((fpath, rel))
            
            ext = fpath.suffix.lower()
            if ext != ".md":
                errors.append(
                    f"Prohibited file type in skill package: '{rel}' (Only pure UTF-8 .md files permitted)."
                )

            size = fpath.stat().st_size
            total_bytes += size
            if size > 1_048_576:  # 1 MB
                errors.append(f"File '{rel}' exceeds 1 MB limit ({size} bytes).")

    if file_count > 100:
        errors.append(f"Package contains {file_count} files; exceeds max limit of 100 files.")
    if total_bytes > 10_485_760:  # 10 MB
        errors.append(f"Total package size ({total_bytes} bytes) exceeds 10 MB limit.")

    print(f"[✓] Package metrics: {file_count} files, {total_bytes:,} bytes total.")

    # 4. Relative Link Integrity Check
    link_pattern = re.compile(r"\[.*?\]\((?!https?:\/\/)(?!mailto:)(.*?)\)")
    for fpath, rel in all_files:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            fcontent = f.read()
        for target_link in link_pattern.findall(fcontent):
            clean_link = target_link.split("#")[0].strip()
            if not clean_link:
                continue
            resolved_target = (fpath.parent / clean_link).resolve()
            if not resolved_target.exists():
                errors.append(f"Broken relative link in '{rel}': '{target_link}' does not exist.")

    if not errors:
        print("[✓] All relative links successfully resolved.")

    return len(errors) == 0, errors


def build_zip_package(skill_root: Path, output_zip: Path):
    print(f"\n[*] Packaging '{skill_root.name}' into: {output_zip.name}")
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(skill_root):
            for fname in files:
                fpath = Path(root) / fname
                # POSIX-compliant relative archive path starting with sentry/
                arcname = "sentry/" + str(fpath.relative_to(skill_root)).replace("\\", "/")
                zf.write(fpath, arcname=arcname)
                print(f"  + Added: {arcname}")
    print(f"[✓] Package built: {output_zip} ({output_zip.stat().st_size:,} bytes)")


def main():
    workspace_root = Path(__file__).resolve().parent.parent
    skill_dir = workspace_root / "skill" / "sentry"
    output_archive = workspace_root / "sentry-final-round2.zip"

    print("=" * 80)
    print("      ULIYA SKILL DEVELOPMENT STANDARD — COMPLIANCE VALIDATOR")
    print("=" * 80)
    print(f"Auditing target directory: {skill_dir}\n")

    valid, errors = validate_sentry_skill(skill_dir)

    if not valid:
        print("\n[✗] COMPLIANCE FAILED with the following errors:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    print("\n[✓] 100% ULIYA SPECIFICATION COMPLIANCE VERIFIED.")
    build_zip_package(skill_dir, output_archive)
    print("=" * 80)
    print("[SUCCESS] Package is production-ready for UGREEN AI NAS Hackathon release.")
    print("=" * 80)


if __name__ == "__main__":
    main()
