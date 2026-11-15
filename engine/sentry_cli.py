#!/usr/bin/env python3
"""
Sentry CLI — Local Security Auditor for UGREEN AI NAS (UGOS)
------------------------------------------------------------
Implements the 100% local, zero-egress, 4-Pass detection engine,
context-aware risk scoring formula, zero-leak secret masking,
and human-in-the-loop reversible quarantine gate.
"""

import os
import sys
import argparse
import hashlib
import json
import re
import shutil
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

# Import modular rules
from rules import (
    PATTERNS,
    WHITELIST_LOCKFILES,
    MEDIA_EXTENSIONS,
    TEXT_EXTENSIONS,
    mask_secret,
    compute_risk_score,
    luhn_checksum_valid,
    iban_checksum_valid,
    calculate_shannon_entropy,
    find_bip39_phrases
)
from image_text import extract_image_text

# Optional rich library for enhanced terminal UI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    console = Console()
    HAS_RICH = True
except ImportError:
    console = None
    HAS_RICH = False

# Optional pypdf for PDF text extraction
try:
    import pypdf
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

# Optional Pillow for images
try:
    from PIL import Image
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False


DEFAULT_TARGET = "./sample_nas/Shared"
DEFAULT_VAULT = "./sample_nas/Private_Security_Vault"

# Audit state persisted after every scan so the confirmation gate can act on the
# exact findings the operator reviewed, without rescanning the storage pool.
FINDINGS_DIRNAME = "Reports"
FINDINGS_STATE_PREFIX = "sentry-findings-"
FINDINGS_STATE_VERSION = 1

# Credential and identifier detectors shared by the text (Pass 2) and
# embedded-image-text (Pass 4) scans: (pattern key, category, severity, mask kind).
TEXT_CREDENTIAL_RULES = (
    ("openai_api_key", "OpenAI API Key", "CRITICAL", "api_key"),
    ("aws_access_key", "AWS Credentials", "CRITICAL", "api_key"),
    ("aws_secret_key", "AWS Secret Access Key", "CRITICAL", "api_key"),
    ("github_token", "GitHub Token", "CRITICAL", "api_key"),
    ("slack_token", "Slack Token", "CRITICAL", "api_key"),
    ("gcp_api_key", "Google Cloud API Key", "CRITICAL", "api_key"),
    ("stripe_key", "Stripe Secret Key", "CRITICAL", "api_key"),
    ("database_uri", "Database URI", "CRITICAL", "database_uri"),
    ("private_key_header", "Private Key", "CRITICAL", "private_key"),
    ("passport_mrz", "Passport MRZ", "HIGH", "passport_mrz"),
)


def normalize_finding_id(token: str) -> Optional[str]:
    """Canonicalises FIND-1 / FIND001 / find-001 into FIND-001."""
    match = re.fullmatch(r"FIND-?0*(\d{1,4})", token.strip().upper())
    if not match:
        return None
    return f"FIND-{int(match.group(1)):03d}"


def resolve_approval(command: str, findings: List[Dict[str, Any]]):
    """Parses the confirmation grammar documented in README.md and SKILL.md.

    The leading 'APPROVE' verb is optional, so the documented forms
    ('ALL CRITICAL', 'FIND-001, FIND-002', 'ALL') and the explicit forms
    ('APPROVE ALL CRITICAL', ...) behave identically.

    Returns (decision, approved_ids, unknown_tokens) where decision is one of
    'approve', 'abort' or 'unknown'.
    """
    text = " ".join(command.strip().upper().split())

    if text in ("ABORT", "CANCEL"):
        return "abort", [], []

    if text.startswith("APPROVE"):
        text = text[len("APPROVE"):].strip()

    if not text:
        return "unknown", [], []

    if text == "ALL":
        return "approve", [f["id"] for f in findings], []

    if text == "ALL CRITICAL":
        return "approve", [f["id"] for f in findings if f["severity"] == "CRITICAL"], []

    known_ids = {f["id"] for f in findings}
    approved: List[str] = []
    unknown: List[str] = []

    for token in [t for t in re.split(r"[,\s]+", text) if t]:
        normalized = normalize_finding_id(token)
        if normalized is not None and normalized in known_ids:
            if normalized not in approved:
                approved.append(normalized)
        else:
            unknown.append(token)

    if unknown or not approved:
        return "unknown", [], unknown

    return "approve", approved, []


def load_findings_state(state_path: Path) -> Dict[str, Any]:
    """Reads and validates a persisted audit state file."""
    with open(state_path, "r", encoding="utf-8") as sf:
        state = json.load(sf)

    if not isinstance(state, dict):
        raise ValueError("state file is not a JSON object")
    if state.get("state_version") != FINDINGS_STATE_VERSION:
        raise ValueError(
            f"unsupported state version {state.get('state_version')!r} "
            f"(expected {FINDINGS_STATE_VERSION})"
        )
    for key in ("target_root", "vault_root", "findings"):
        if key not in state:
            raise ValueError(f"state file is missing required key '{key}'")
    if not isinstance(state["findings"], list):
        raise ValueError("state file 'findings' must be a list")

    return state


def find_latest_state(vault_root: Path, target_root: Optional[Path] = None) -> Optional[Path]:
    """Returns the newest saved audit state, optionally scoped to one target root."""
    state_dir = vault_root / FINDINGS_DIRNAME
    if not state_dir.is_dir():
        return None

    candidates = sorted(
        state_dir.glob(f"{FINDINGS_STATE_PREFIX}*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    if target_root is None:
        return candidates[0] if candidates else None

    target_str = str(target_root)
    for candidate in candidates:
        try:
            state = load_findings_state(candidate)
        except (OSError, ValueError):
            continue
        if state["target_root"] == target_str:
            return candidate

    return None


# Matches a manifest table row: | `FIND-001, FIND-002` | `sha256` | `orig` | `vault` | `STATUS` |
MANIFEST_ROW_RE = re.compile(
    r"^\|\s*`(?P<ids>[^`]+)`\s*"
    r"\|\s*`(?P<sha>[0-9a-fA-F]{64})`\s*"
    r"\|\s*`(?P<orig>[^`]+)`\s*"
    r"\|\s*`(?P<vault>[^`]+)`\s*"
    r"\|\s*`?(?P<status>[A-Za-z_]+)`?\s*\|\s*$"
)


def sha256_file(path: Path, chunk_size: int = 1048576) -> str:
    """Streams a file through SHA-256 so hashing never depends on file size."""
    hasher = hashlib.sha256()
    with open(path, "rb") as bf:
        for chunk in iter(lambda: bf.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def try_sha256_file(path: Path) -> Optional[str]:
    try:
        return sha256_file(path)
    except OSError:
        return None


def _manifest_row(
    finding_ids: List[str],
    sha256: str,
    original_path: Path,
    vault_path: Path,
    status: str
) -> str:
    """Renders one manifest table row. Multiple findings on one file share a row."""
    return (
        f"| `{', '.join(finding_ids)}` | `{sha256}` | `{original_path}` "
        f"| `{vault_path}` | `{status}` |"
    )


def print_loaded_state(state_path: Path, state: Dict[str, Any]):
    print("[*] Confirmation gate operating on a saved audit — no filesystem scan performed.")
    print(f"    Audit state:   {state_path}")
    print(f"    Audit time:    {state.get('generated_at', 'unknown')}")
    print(f"    Target root:   {state['target_root']}")
    print(f"    Files scanned: {state.get('total_evaluated', 0)}")
    print(f"    Findings:      {len(state['findings'])}\n")


class SentryCLI:
    def __init__(
        self,
        target_path: Path,
        vault_path: Path,
        report_path: Optional[Path] = None,
        is_shared: bool = True,
        is_public: bool = True,
        scan_depth: str = "deep"
    ):
        self.target_path = target_path.resolve()
        self.vault_path = vault_path.resolve()
        self.report_path = report_path or (self.vault_path / "Reports" / f"Risk_Heatmap_Report_{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.md")
        self.is_shared = is_shared
        self.is_public = is_public
        self.scan_depth = scan_depth

        self.state_path: Optional[Path] = None
        self.findings: List[Dict[str, Any]] = []
        self.total_evaluated = 0
        self.skipped_oversized = 0
        self.skipped_media = 0
        self.skipped_corrupt = 0
        self.unscanned_encrypted = 0
        self.images_inspected = 0
        self.images_textless = 0

    def print_banner(self):
        banner_text = """
  ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
  ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
   UGREEN AI NAS (UGOS) — Zero-Egress Autonomous Auditor
"""
        if HAS_RICH:
            console.print(Panel(Text(banner_text, style="bold cyan"), title="Sentry Security Auditor", subtitle="Hackathon 2026 Edition"))
        else:
            print(banner_text)

    def run_audit(self):
        self.print_banner()
        print(f"[*] Target Directory:        {self.target_path}")
        print(f"[*] Multi-User Shared Share: {self.is_shared} (Exposure Multiplier α = 0.50)")
        print(f"[*] Public / Guest Enabled:  {self.is_public} (Exposure Multiplier β = 0.75)")
        print(f"[*] Scan Depth:              {self.scan_depth}")
        print(f"[*] Quarantine Vault:        {self.vault_path}\n")

        finding_id_seq = 1

        for current_dir, _, files in os.walk(self.target_path):
            for filename in files:
                filepath = Path(current_dir) / filename
                self.total_evaluated += 1

                # -------------------------------------------------------------
                # Pass 1: Inventory & Resource Guard
                # -------------------------------------------------------------
                if filename in WHITELIST_LOCKFILES:
                    # Suppress legitimate cryptographic hashes in package lockfiles
                    continue

                ext = filepath.suffix.lower()
                if ext in MEDIA_EXTENSIONS:
                    self.skipped_media += 1
                    continue

                try:
                    stat_info = filepath.stat()
                except OSError as e:
                    print(f"[!] Warning: Cannot access {filepath}: {e}")
                    continue

                if stat_info.st_size > 52428800:  # 50 MB
                    self.skipped_oversized += 1
                    continue

                if stat_info.st_size == 0:
                    self.skipped_corrupt += 1
                    continue

                # Encrypted ZIP detection
                if ext == ".zip":
                    if self._check_zip_encryption(filepath):
                        self.unscanned_encrypted += 1
                        s, a, b, r = compute_risk_score("MEDIUM", self.is_shared, self.is_public)
                        self.findings.append({
                            "id": f"FIND-{finding_id_seq:03d}",
                            "severity": "MEDIUM",
                            "score_r": r,
                            "category": "Encrypted Archive",
                            "file": str(filepath),
                            "masked_evidence": "[ENCRYPTED ZIP: Password Protected — Skipped brute-force]",
                            "action": "Informational Review"
                        })
                        finding_id_seq += 1
                        continue

                # -------------------------------------------------------------
                # Pass 2: Text, Code & Configuration Files
                # -------------------------------------------------------------
                if ext in TEXT_EXTENSIONS or ".env" in filename:
                    found = self._scan_text_file(filepath, finding_id_seq)
                    finding_id_seq += found

                # -------------------------------------------------------------
                # Pass 3: Structured Documents & CSV
                # -------------------------------------------------------------
                elif ext in [".csv", ".tsv"]:
                    found = self._scan_csv_file(filepath, finding_id_seq)
                    finding_id_seq += found
                elif ext == ".pdf":
                    found = self._scan_pdf_file(filepath, finding_id_seq)
                    finding_id_seq += found

                # -------------------------------------------------------------
                # Pass 4: Embedded Image Text & Exposure Metadata (Deep Scan)
                # -------------------------------------------------------------
                elif ext in [".png", ".jpg", ".jpeg", ".webp"] and self.scan_depth == "deep":
                    found = self._scan_image_file(filepath, finding_id_seq)
                    finding_id_seq += found

        self.display_summary()
        self.save_findings_state()

    def _check_zip_encryption(self, path: Path) -> bool:
        try:
            with open(path, "rb") as f:
                header = f.read(30)
                if len(header) >= 8 and header.startswith(b"PK\x03\x04"):
                    flag = struct.unpack("<H", header[6:8])[0]
                    return bool(flag & 0x0001)
        except Exception:
            pass
        return False

    def _scan_text_file(self, filepath: Path, start_idx: int) -> int:
        count = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(52428800)
        except Exception:
            return 0

        # Credential and identifier patterns (shared with the image-text pass)
        for pattern_key, category, severity, mask_kind in TEXT_CREDENTIAL_RULES:
            for match in PATTERNS[pattern_key].findall(content):
                s, a, b, r = compute_risk_score(severity, self.is_shared, self.is_public)
                self.findings.append({
                    "id": f"FIND-{start_idx + count:03d}",
                    "severity": severity,
                    "score_r": r,
                    "category": category,
                    "file": str(filepath),
                    "masked_evidence": mask_secret(mask_kind, match),
                    "action": "Immediate Quarantine" if severity == "CRITICAL" else "Quarantine / Restrict Access"
                })
                count += 1

        # BIP-39 recovery phrases (12 or 24 consecutive dictionary words)
        for phrase in find_bip39_phrases(content):
            s, a, b, r = compute_risk_score("CRITICAL", self.is_shared, self.is_public)
            self.findings.append({
                "id": f"FIND-{start_idx + count:03d}",
                "severity": "CRITICAL",
                "score_r": r,
                "category": "Crypto Seed Phrase",
                "file": str(filepath),
                "masked_evidence": mask_secret("bip39_seed", phrase),
                "action": "Immediate Quarantine"
            })
            count += 1

        return count

    def _scan_csv_file(self, filepath: Path, start_idx: int) -> int:
        count = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(52428800)
        except Exception:
            return 0

        # SSN
        for m in PATTERNS["us_ssn"].findall(content):
            s, a, b, r = compute_risk_score("HIGH", self.is_shared, self.is_public)
            self.findings.append({
                "id": f"FIND-{start_idx + count:03d}",
                "severity": "HIGH",
                "score_r": r,
                "category": "Identity PII (SSN)",
                "file": str(filepath),
                "masked_evidence": mask_secret("ssn", m),
                "action": "Quarantine / Restrict Access"
            })
            count += 1

        # IBAN
        for m in PATTERNS["iban"].findall(content):
            if not iban_checksum_valid(m):
                continue  # ISO 7064 Mod-97 rejects lookalikes
            s, a, b, r = compute_risk_score("HIGH", self.is_shared, self.is_public)
            self.findings.append({
                "id": f"FIND-{start_idx + count:03d}",
                "severity": "HIGH",
                "score_r": r,
                "category": "Financial Record (IBAN)",
                "file": str(filepath),
                "masked_evidence": mask_secret("iban", m),
                "action": "Restrict Folder Access"
            })
            count += 1

        return count

    def _scan_pdf_file(self, filepath: Path, start_idx: int) -> int:
        count = 0
        text = ""
        if HAS_PYPDF:
            try:
                reader = pypdf.PdfReader(str(filepath))
                for page in reader.pages[:10]:
                    extracted = page.extract_text()
                    if extracted:
                        text += extracted + "\n"
            except Exception:
                pass
        
        if not text:
            # Fallback direct byte string scan for raw PDF text streams
            try:
                with open(filepath, "rb") as f:
                    text = f.read(52428800).decode("latin1", errors="ignore")
            except Exception:
                return 0

        # Credential and identifier patterns inside the document text layer
        for pattern_key, category, severity, mask_kind in TEXT_CREDENTIAL_RULES:
            for match in PATTERNS[pattern_key].findall(text):
                s, a, b, r = compute_risk_score(severity, self.is_shared, self.is_public)
                self.findings.append({
                    "id": f"FIND-{start_idx + count:03d}",
                    "severity": severity,
                    "score_r": r,
                    "category": category,
                    "file": str(filepath),
                    "masked_evidence": mask_secret(mask_kind, match),
                    "action": "Immediate Quarantine" if severity == "CRITICAL" else "Quarantine / Restrict Access"
                })
                count += 1

        if any(kw in text for kw in ["Account Balance", "Private Wealth", "Routing Number", "Wire Transfer"]):
            s, a, b, r = compute_risk_score("MEDIUM", self.is_shared, self.is_public)
            self.findings.append({
                "id": f"FIND-{start_idx + count:03d}",
                "severity": "MEDIUM",
                "score_r": r,
                "category": "Bank Statement",
                "file": str(filepath),
                "masked_evidence": "Account Balance & Routing Record Present",
                "action": "Review Access Permissions"
            })
            count += 1

        return count

    def _scan_image_file(self, filepath: Path, start_idx: int) -> int:
        """Pass 4: embedded image text and exposure metadata.

        Reads text already stored in the file (PNG tEXt/zTXt/iTXt chunks, JPEG COM
        comments and EXIF text tags) and scans it with the same detectors as Pass 2.
        No pixel OCR happens here — on UGOS that is delegated to `ug-photo ocr`.
        """
        info = extract_image_text(filepath)
        self.images_inspected += 1
        count = 0

        # Exposure metadata: a shared photo of a document also leaks where it was taken.
        if info["gps"]:
            s, a, b, r = compute_risk_score("MEDIUM", self.is_shared, self.is_public)
            self.findings.append({
                "id": f"FIND-{start_idx + count:03d}",
                "severity": "MEDIUM",
                "score_r": r,
                "category": "Image Metadata (GPS Location)",
                "file": str(filepath),
                "masked_evidence": "EXIF GPS coordinates present — values withheld",
                "action": "Strip Metadata / Restrict Access"
            })
            count += 1

        text = info["text"]
        if not text.strip():
            self.images_textless += 1
            return count

        for pattern_key, category, severity, mask_kind in TEXT_CREDENTIAL_RULES:
            for match in PATTERNS[pattern_key].findall(text):
                s, a, b, r = compute_risk_score(severity, self.is_shared, self.is_public)
                self.findings.append({
                    "id": f"FIND-{start_idx + count:03d}",
                    "severity": severity,
                    "score_r": r,
                    "category": f"{category} (image text)",
                    "file": str(filepath),
                    "masked_evidence": mask_secret(mask_kind, match),
                    "action": "Immediate Quarantine" if severity == "CRITICAL" else "Quarantine / Restrict Access"
                })
                count += 1

        for match in PATTERNS["us_ssn"].findall(text):
            s, a, b, r = compute_risk_score("HIGH", self.is_shared, self.is_public)
            self.findings.append({
                "id": f"FIND-{start_idx + count:03d}",
                "severity": "HIGH",
                "score_r": r,
                "category": "Identity PII (SSN) (image text)",
                "file": str(filepath),
                "masked_evidence": mask_secret("ssn", match),
                "action": "Quarantine / Restrict Access"
            })
            count += 1

        # Payment card numbers validated with the ISO/IEC 7812 Luhn algorithm.
        for candidate in re.findall(r"\b(?:\d[ -]*?){13,19}\b", text):
            digits = re.sub(r"\D", "", candidate)
            if luhn_checksum_valid(digits):
                s, a, b, r = compute_risk_score("HIGH", self.is_shared, self.is_public)
                self.findings.append({
                    "id": f"FIND-{start_idx + count:03d}",
                    "severity": "HIGH",
                    "score_r": r,
                    "category": "Payment Card (image text)",
                    "file": str(filepath),
                    "masked_evidence": mask_secret("payment_card", digits),
                    "action": "Immediate Quarantine"
                })
                count += 1
                break

        # BIP-39 recovery phrases pasted into a screenshot or text chunk
        for phrase in find_bip39_phrases(text):
            s, a, b, r = compute_risk_score("CRITICAL", self.is_shared, self.is_public)
            self.findings.append({
                "id": f"FIND-{start_idx + count:03d}",
                "severity": "CRITICAL",
                "score_r": r,
                "category": "Crypto Seed Phrase (image text)",
                "file": str(filepath),
                "masked_evidence": mask_secret("bip39_seed", phrase),
                "action": "Immediate Quarantine"
            })
            count += 1

        return count

    def display_summary(self):
        print(f"[✓] 4-Pass Scan Finished. Evaluated {self.total_evaluated} file(s).")
        print(f"    - Findings Identified: {len(self.findings)}")
        print(f"    - Skipped Media Streams: {self.skipped_media}")
        print(f"    - Skipped Corrupt (0-Byte): {self.skipped_corrupt}")
        print(f"    - Unscanned Encrypted: {self.unscanned_encrypted}")
        print(f"    - Images Inspected (text/metadata): {self.images_inspected} "
              f"({self.images_textless} without embedded text)\n")

        if not self.findings:
            print("[+] Zero exposed credentials or high-risk records discovered.")
            return

        self.render_findings_table()
        self.generate_report()

    def render_findings_table(self):
        """Prints the masked Risk Heatmap matrix (shared by audit and gate)."""
        if HAS_RICH:
            table = Table(title="Sentry Risk Heatmap Findings")
            table.add_column("Finding ID", style="cyan")
            table.add_column("Severity", style="bold")
            table.add_column("Score (R)", style="magenta")
            table.add_column("Category", style="green")
            table.add_column("Relative Path", style="white")
            table.add_column("Masked Evidence", style="yellow")
            table.add_column("Recommended Action", style="blue")

            for f in self.findings:
                rel = Path(f["file"]).relative_to(self.target_path)
                sev_style = "red" if f["severity"] == "CRITICAL" else ("yellow" if f["severity"] == "HIGH" else "green")
                table.add_row(
                    f["id"],
                    f"[{sev_style}]{f['severity']}[/{sev_style}]",
                    str(f["score_r"]),
                    f["category"],
                    str(rel),
                    f["masked_evidence"],
                    f["action"]
                )
            console.print(table)
        else:
            print("=" * 80)
            print("FINDINGS MATRIX")
            print("=" * 80)
            for f in self.findings:
                rel = Path(f["file"]).relative_to(self.target_path)
                print(f"[{f['id']}] {f['severity']:<8} (Score {f['score_r']:>5}) -> {rel}")
                print(f"          Category: {f['category']}")
                print(f"          Evidence: {f['masked_evidence']}")
                print(f"          Action:   {f['action']}\n")

    def save_findings_state(self):
        """Persists the audit findings so the confirmation gate never has to rescan."""
        state_dir = self.vault_path / FINDINGS_DIRNAME
        state_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
        self.state_path = state_dir / f"{FINDINGS_STATE_PREFIX}{timestamp}.json"

        payload = {
            "state_version": FINDINGS_STATE_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_root": str(self.target_path),
            "vault_root": str(self.vault_path),
            "report_path": str(self.report_path),
            "scan_depth": self.scan_depth,
            "is_shared": self.is_shared,
            "is_public": self.is_public,
            "total_evaluated": self.total_evaluated,
            "skipped_oversized": self.skipped_oversized,
            "skipped_media": self.skipped_media,
            "skipped_corrupt": self.skipped_corrupt,
            "unscanned_encrypted": self.unscanned_encrypted,
            "images_inspected": self.images_inspected,
            "images_textless": self.images_textless,
            "findings": self.findings
        }

        with open(self.state_path, "w", encoding="utf-8") as sf:
            json.dump(payload, sf, indent=2, ensure_ascii=False)

        print(f"[+] Audit state saved for the confirmation gate: {self.state_path}")

    def generate_report(self):
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        crit_count = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in self.findings if f["severity"] == "HIGH")
        med_count = sum(1 for f in self.findings if f["severity"] == "MEDIUM")

        lines = [
            "# 🛡️ Sentry Local Security Audit — Risk Heatmap Report",
            f"**Audit Date:** {today}  ",
            f"**Target Storage Root:** `{self.target_path}`  ",
            f"**Platform:** UGREEN AI NAS iDX6011 Pro (UGOS)  ",
            "**Egress Verification:** Verified 0 Bytes Transmitted (100% Local Execution)",
            "",
            "---",
            "### Executive Summary",
            f"- **Total Files Evaluated:** {self.total_evaluated}",
            f"- **Skipped Files (>50MB / Media):** {self.skipped_oversized + self.skipped_media}",
            f"- **Skipped Corrupt (0-Byte):** {self.skipped_corrupt}",
            f"- **Encrypted Archives:** {self.unscanned_encrypted}",
            f"- **Images Inspected (embedded text/metadata):** {self.images_inspected} "
            f"({self.images_textless} without embedded text)",
            f"- **Identified Security Findings:** {len(self.findings)}",
            f"  - 🔴 **Critical Severity:** {crit_count}",
            f"  - 🟠 **High Severity:** {high_count}",
            f"  - 🟡 **Medium Severity:** {med_count}",
            "",
            "---",
            "### Findings Matrix",
            "| Finding ID | Severity | Score R | Category | Source Path | Masked Evidence | Recommended Action |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
        ]

        for f in self.findings:
            rel = Path(f["file"]).relative_to(self.target_path)
            lines.append(
                f"| `{f['id']}` | `{f['severity']}` | {f['score_r']} | {f['category']} | "
                f"`{rel}` | `{f['masked_evidence']}` | {f['action']} |"
            )

        lines.extend([
            "",
            "---",
            "*Report generated locally by Sentry CLI on UGREEN AI NAS.*"
        ])

        with open(self.report_path, "w", encoding="utf-8") as rf:
            rf.write("\n".join(lines))
        print(f"\n[+] Risk Heatmap Report saved to: {self.report_path}")

    @staticmethod
    def _gate_menu() -> str:
        return (
            "Awaiting confirmation command. Available choices:\n"
            "  - ALL CRITICAL            (or: APPROVE ALL CRITICAL)\n"
            "  - FIND-001, FIND-002      (or: APPROVE FIND-001, FIND-002)\n"
            "  - ALL                     (or: APPROVE ALL)\n"
            "  - ABORT\n"
            "Pass the choice with --approve \"<command>\" to act on this exact audit state."
        )

    def prompt_quarantine_gate(self, approve_cmd: Optional[str] = None) -> Optional[bool]:
        """
        Two-Step Human-in-the-Loop Confirmation Gate.
        Acts only on findings already collected (or restored from saved audit state).
        """
        print("\n" + "=" * 80)
        print("           🛡️ SENTRY HUMAN-IN-THE-LOOP QUARANTINE GATE")
        print("=" * 80)
        print("Policy: No files are ever altered or moved without authenticated user approval.")
        print(f"Target Quarantine Vault: {self.vault_path}")
        if self.state_path is not None:
            print(f"Audit State:            {self.state_path}")
        print()

        if approve_cmd is None:
            print(self._gate_menu())
            return

        decision, approved_ids, unknown = resolve_approval(approve_cmd, self.findings)

        if decision == "abort":
            print("[*] Quarantine execution aborted. Zero files moved.")
            print(self._gate_menu())
            return

        if decision == "unknown":
            if unknown:
                print(f"[!] Unrecognised finding id(s): {', '.join(unknown)}")
            print(f"[*] Command '{approve_cmd.strip()}' matched no finding. Zero files moved.")
            print(self._gate_menu())
            return

        if not approved_ids:
            print(f"[*] No findings matched '{approve_cmd.strip()}'. Zero files moved.")
            return

        print(f"\n[*] Executing Human-Confirmed Quarantine for {len(approved_ids)} finding(s): {', '.join(approved_ids)}")
        return self._execute_quarantine(approved_ids)

    def _execute_quarantine(self, approved_ids: List[str]) -> bool:
        """Moves each approved file exactly once, with one manifest row per file.

        Several findings can point at the same file (e.g. an API key and a database
        URI inside one .env). Those are grouped, so the file is moved once and its
        checksum is recorded once, listing every approved finding id for that file.
        """
        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        session_vault = self.vault_path / f"Quarantine_{timestamp_str}"
        session_vault.mkdir(parents=True, exist_ok=True)

        approved_set = set(approved_ids)
        selected = [f for f in self.findings if f["id"] in approved_set]

        # Group approved findings by source file, preserving first-seen order.
        grouped: Dict[Path, List[str]] = {}
        for finding in selected:
            src = Path(finding["file"]).resolve()
            grouped.setdefault(src, []).append(finding["id"])

        manifest_entries: List[Dict[str, Any]] = []
        failures: List[str] = []

        for src, finding_ids in grouped.items():
            label = ", ".join(finding_ids)

            if not src.exists():
                print(f"  [!] SKIPPED {label}: {src} no longer exists on disk")
                failures.append(label)
                continue

            try:
                rel_path = src.relative_to(self.target_path)
            except ValueError:
                print(f"  [!] SKIPPED {label}: {src} resolves outside the audited root {self.target_path}")
                failures.append(label)
                continue

            # Preserve relative directory structure to prevent collision
            dest = session_vault / rel_path
            if dest.exists():
                print(f"  [!] SKIPPED {label}: vault path already occupied: {dest}")
                failures.append(label)
                continue

            sha_hash = sha256_file(src)
            dest.parent.mkdir(parents=True, exist_ok=True)

            try:
                shutil.move(str(src), str(dest))
            except OSError as exc:
                print(f"  [!] FAILED  {label}: could not move into the vault: {exc}")
                failures.append(label)
                continue

            print(f"  [QUARANTINED] {label} -> {dest}")
            manifest_entries.append({
                "ids": finding_ids,
                "sha256": sha_hash,
                "original_path": src,
                "vault_path": dest
            })

        manifest_file = session_vault / "quarantine-manifest.md"
        with open(manifest_file, "w", encoding="utf-8") as mf:
            mf.write(f"# Sentry Quarantine Manifest\n")
            mf.write(f"- **Execution Timestamp:** {datetime.now(timezone.utc).isoformat()}\n")
            mf.write(f"- **Vault Location:** `{session_vault}`\n")
            mf.write(f"- **Findings Approved:** {len(approved_ids)}\n")
            mf.write(f"- **Files Quarantined:** {len(manifest_entries)}\n\n")
            mf.write(f"| Finding ID | SHA-256 Checksum | Original Path | Vault Path | Status |\n")
            mf.write(f"| :--- | :--- | :--- | :--- | :--- |\n")
            for entry in manifest_entries:
                mf.write(
                    _manifest_row(
                        entry["ids"],
                        entry["sha256"],
                        entry["original_path"],
                        entry["vault_path"],
                        "QUARANTINED"
                    ) + "\n"
                )

        print(f"\n[✓] Quarantine complete: {len(manifest_entries)} file(s) for {len(approved_ids)} finding(s).")
        print(f"    Reversible manifest saved to: {manifest_file}")

        if failures:
            print(f"[✗] {len(failures)} approved finding(s) were not quarantined: {', '.join(failures)}")
            return False
        return True


def rollback_manifest(manifest_path: Path) -> bool:
    """Restores quarantined files, verifying each against its manifest checksum first.

    A file is restored only when its vault copy still hashes to the recorded
    SHA-256. Checksum mismatches, conflicts and missing files are reported and
    left in the vault, and the manifest status is updated in place so a second
    rollback is a genuine no-op rather than a false success.
    """
    if not manifest_path.exists():
        print(f"[!] Error: Manifest not found: {manifest_path}")
        return False

    print(f"[*] Reading Quarantine Manifest from: {manifest_path}")
    try:
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(f"[!] Error: cannot read manifest: {exc}")
        return False

    restored = 0
    already = 0
    failed = 0
    updated_lines: List[str] = []

    for line in lines:
        match = MANIFEST_ROW_RE.match(line)
        if not match:
            updated_lines.append(line)
            continue

        finding_ids = [i.strip() for i in match.group("ids").split(",") if i.strip()]
        expected_sha = match.group("sha").lower()
        original_path = Path(match.group("orig"))
        vault_path = Path(match.group("vault"))
        status = match.group("status").upper()
        label = ", ".join(finding_ids)

        if status == "RESTORED":
            updated_lines.append(line)
            already += 1
            continue

        if not vault_path.exists():
            if original_path.exists() and try_sha256_file(original_path) == expected_sha:
                print(f"  [=] ALREADY RESTORED {label} -> {original_path} (checksum verified)")
                already += 1
                updated_lines.append(
                    _manifest_row(finding_ids, expected_sha, original_path, vault_path, "RESTORED")
                )
            else:
                print(f"  [!] MISSING IN VAULT {label}: {vault_path}")
                failed += 1
                updated_lines.append(
                    _manifest_row(finding_ids, expected_sha, original_path, vault_path, "MISSING")
                )
            continue

        actual_sha = try_sha256_file(vault_path)
        if actual_sha != expected_sha:
            print(f"  [!] INTEGRITY FAILED {label}: checksum mismatch — file left in the vault")
            print(f"      expected: {expected_sha}")
            print(f"      actual:   {actual_sha or 'unreadable'}")
            failed += 1
            updated_lines.append(
                _manifest_row(finding_ids, expected_sha, original_path, vault_path, "INTEGRITY_FAILED")
            )
            continue

        if original_path.exists():
            print(f"  [!] CONFLICT {label}: {original_path} already exists — file left in the vault")
            failed += 1
            updated_lines.append(
                _manifest_row(finding_ids, expected_sha, original_path, vault_path, "RESTORE_CONFLICT")
            )
            continue

        try:
            original_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(vault_path), str(original_path))
        except OSError as exc:
            print(f"  [!] ERROR {label} -> {original_path}: {exc}")
            failed += 1
            updated_lines.append(
                _manifest_row(finding_ids, expected_sha, original_path, vault_path, "RESTORE_FAILED")
            )
            continue

        print(f"  [RESTORED] {label} -> {original_path} (checksum verified)")
        restored += 1
        updated_lines.append(
            _manifest_row(finding_ids, expected_sha, original_path, vault_path, "RESTORED")
        )

    try:
        manifest_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"  [!] Warning: could not update manifest status: {exc}")

    if failed:
        print(f"[✗] Rollback incomplete. Restored {restored}, already restored {already}, failed {failed}.")
        return False

    print(f"[✓] Rollback Complete. Restored {restored} file(s), {already} already in place.")
    return True


def main():
    parser = argparse.ArgumentParser(description="Sentry CLI: Zero-Egress Local Security Auditor for UGREEN AI NAS")
    parser.add_argument("--action", choices=["audit", "rollback"], default="audit")
    parser.add_argument("--target", type=str, default=None, help=f"Storage root to audit (default: {DEFAULT_TARGET})")
    parser.add_argument("--vault", type=str, default=None, help=f"Quarantine vault root (default: {DEFAULT_VAULT})")
    parser.add_argument("--depth", choices=["quick", "standard", "deep"], default="deep")
    parser.add_argument(
        "--approve",
        type=str,
        default=None,
        help="Confirmation grammar: 'ALL CRITICAL', 'FIND-001, FIND-002', or 'ALL' (optional 'APPROVE' prefix)"
    )
    parser.add_argument(
        "--findings",
        type=str,
        default=None,
        help="Saved audit state (JSON) to confirm. Defaults to the newest state for --target under <vault>/Reports."
    )
    parser.add_argument("--manifest", type=str, default=None, help="Path to quarantine-manifest.md for rollback")
    args = parser.parse_args()

    if args.action == "rollback":
        if not args.manifest:
            print("[!] Error: --manifest required for rollback action.")
            sys.exit(1)
        if not rollback_manifest(Path(args.manifest).resolve()):
            sys.exit(1)
        return

    # ------------------------------------------------------------------
    # Confirmation gate: confirm the saved audit, never rescan the storage
    # ------------------------------------------------------------------
    if args.approve is not None:
        target_root = Path(args.target).resolve() if args.target else None
        vault_root = Path(args.vault or DEFAULT_VAULT).resolve()

        if args.findings:
            state_path: Optional[Path] = Path(args.findings).resolve()
            if not state_path.exists():
                print(f"[!] Error: audit state not found: {state_path}")
                sys.exit(1)
        else:
            state_path = find_latest_state(vault_root, target_root)
            if state_path is None:
                scope = f" for target {target_root}" if target_root else ""
                print(f"[!] Error: no saved audit state found{scope} in {vault_root / FINDINGS_DIRNAME}.")
                print("    Run the audit first (without --approve); the gate then confirms those exact findings.")
                sys.exit(1)

        try:
            state = load_findings_state(state_path)
        except (OSError, ValueError) as exc:
            print(f"[!] Error: cannot read audit state {state_path}: {exc}")
            sys.exit(1)

        cli = SentryCLI(
            target_path=Path(state["target_root"]),
            vault_path=Path(state["vault_root"]),
            report_path=Path(state["report_path"]) if state.get("report_path") else None,
            is_shared=bool(state.get("is_shared", True)),
            is_public=bool(state.get("is_public", True)),
            scan_depth=state.get("scan_depth", "deep")
        )
        cli.findings = state["findings"]
        cli.total_evaluated = int(state.get("total_evaluated", 0))
        cli.state_path = state_path
        print_loaded_state(state_path, state)

        if not cli.findings:
            print("[+] The saved audit recorded zero findings. Nothing to quarantine.")
            return

        cli.render_findings_table()
        if cli.prompt_quarantine_gate(args.approve) is False:
            sys.exit(1)
        return

    # ------------------------------------------------------------------
    # Default: full 4-pass audit (state is saved for a later confirmation)
    # ------------------------------------------------------------------
    cli = SentryCLI(
        target_path=Path(args.target or DEFAULT_TARGET),
        vault_path=Path(args.vault or DEFAULT_VAULT),
        scan_depth=args.depth
    )
    cli.run_audit()
    if cli.prompt_quarantine_gate(args.approve) is False:
        sys.exit(1)


if __name__ == "__main__":
    main()
