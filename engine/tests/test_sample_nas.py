"""The shipped synthetic NAS fixture set must exercise all four passes."""

import shutil
from pathlib import Path

import pytest

from sentry_cli import SentryCLI, rollback_manifest

ENGINE_DIR = Path(__file__).resolve().parents[1]
SAMPLE_SHARE = ENGINE_DIR / "sample_nas" / "Shared"

EXPECTED_FIXTURES = [
    "Projects/app1/.env",
    "Projects/app1/index.js",
    "Projects/app1/package-lock.json",
    "Projects/app2/.env",
    "Backups/wallet_seed.txt",
    "Projects/app1/deploy-secrets.txt",
    "Finance/payroll_2026.csv",
    "Documents/Bank_Statement_Jan2026.pdf",
    "Documents/corrupt_doc.pdf",
    "Documents/meeting_notes.md",
    "Documents/passport_mrz.txt",
    "Archives/encrypted_keys.zip",
    "Photos/payment_card.png",
    "Photos/vacation.jpg",
    "Photos/camera_upload.jpg",
    "Media/product_demo.mp4",
]

RAW_SECRETS = [
    "sk-live-TESTING993848194810284729184810",
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "V3ryS3cur3Passw0rd!",
    "abandon ability able about above absent absorb abstract absurd abuse access accident",
    "4111 1111 1111 1111",
    "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx",
    "AIzaSyA1234567890abcdefghijklmnopqrstuv",
    "sk_live_abcdefghijklmnopqrstuvwx",
    "P<UTOERIKSSON<<ANNA<MARIA",
]


@pytest.mark.parametrize("relative_path", EXPECTED_FIXTURES)
def test_fixture_present(relative_path):
    assert (SAMPLE_SHARE / relative_path).is_file(), (
        f"missing fixture {relative_path}; run engine/sample_nas/generate_fixtures.py"
    )


@pytest.fixture(scope="module")
def sample_scan(tmp_path_factory):
    vault = tmp_path_factory.mktemp("sample-vault")
    cli = SentryCLI(target_path=SAMPLE_SHARE, vault_path=vault, scan_depth="deep")
    cli.run_audit()
    return cli


def test_all_four_passes_produce_findings(sample_scan):
    categories = {finding["category"] for finding in sample_scan.findings}

    # Pass 1 — resource guard and encrypted archive handling
    assert "Encrypted Archive" in categories

    # Pass 2 — text, code and configuration secrets
    assert {
        "OpenAI API Key",
        "Database URI",
        "AWS Credentials",
        "AWS Secret Access Key",
        "GitHub Token",
        "Slack Token",
        "Google Cloud API Key",
        "Stripe Secret Key",
        "Crypto Seed Phrase",
    } <= categories

    # Pass 3 — structured documents and financial records
    assert {
        "Identity PII (SSN)",
        "Financial Record (IBAN)",
        "Bank Statement",
        "Passport MRZ",
    } <= categories

    # Pass 4 — embedded image text and exposure metadata
    assert {
        "Payment Card (image text)",
        "Image Metadata (GPS Location)",
    } <= categories


def test_pass_counters_reflect_the_fixture_edges(sample_scan):
    assert sample_scan.skipped_corrupt == 1, "corrupt_doc.pdf should be recorded as corrupt"
    assert sample_scan.skipped_media == 1, "the .mp4 container must be skipped"
    assert sample_scan.unscanned_encrypted == 1
    assert sample_scan.images_inspected == 3
    assert sample_scan.images_textless == 2, "vacation.jpg and camera_upload.jpg carry no text"
    assert sample_scan.skipped_oversized == 0


def test_expected_finding_volume(sample_scan):
    # 2 app1 .env + 2 app2 .env + 1 seed + 4 deploy tokens + 4 payroll
    # + 1 PDF + 1 MRZ + 1 zip + 1 card + 1 GPS
    assert len(sample_scan.findings) == 18
    severities = [f["severity"] for f in sample_scan.findings]
    assert severities.count("CRITICAL") == 9
    assert severities.count("HIGH") == 6
    assert severities.count("MEDIUM") == 3


def test_report_and_saved_state_never_contain_raw_secrets(sample_scan):
    documents = [
        path.read_text(encoding="utf-8", errors="ignore")
        for path in sample_scan.vault_path.glob("Reports/*")
        if path.suffix in (".md", ".json")
    ]
    assert documents, "audit should have written a report and a state file"

    combined = "\n".join(documents)
    for secret in RAW_SECRETS:
        assert secret not in combined, f"raw secret leaked into audit output: {secret[:12]}..."


def test_two_env_files_quarantine_to_distinct_paths(tmp_path):
    """`Projects/app1/.env` and `Projects/app2/.env` must not collide in the vault."""
    share = tmp_path / "Shared"
    shutil.copytree(SAMPLE_SHARE, share)
    vault = tmp_path / "Vault"

    originals = {
        path.relative_to(share): path.read_bytes()
        for path in share.rglob("*")
        if path.is_file()
    }

    cli = SentryCLI(target_path=share, vault_path=vault, scan_depth="deep")
    cli.run_audit()
    critical_ids = [f["id"] for f in cli.findings if f["severity"] == "CRITICAL"]
    assert cli._execute_quarantine(critical_ids) is True

    env_files = sorted(path.relative_to(vault).as_posix() for path in vault.rglob(".env"))
    assert len(env_files) == 2
    assert env_files[0].endswith("Projects/app1/.env")
    assert env_files[1].endswith("Projects/app2/.env")

    manifest = next(vault.glob("Quarantine_*/quarantine-manifest.md"))
    assert rollback_manifest(manifest) is True

    for relative_path, content in originals.items():
        assert (share / relative_path).read_bytes() == content, f"{relative_path} not restored intact"
