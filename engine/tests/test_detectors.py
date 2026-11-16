"""Credential detectors wired into the scan, and the full BIP-39 dictionary."""

import json

import pytest

from generate_fixtures import build_pdf
from rules import BIP39_WORDLIST, PATTERNS, mask_secret

GITHUB_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
GCP_API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwx"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SLACK_2PART = "xoxb-123456789012-abcdefghijklmnopqrstuvwx"
SLACK_3PART = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
MRZ = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"


@pytest.mark.parametrize(
    "category, line, raw_token",
    [
        ("AWS Secret Access Key", f"aws_secret_access_key = {AWS_SECRET}", AWS_SECRET),
        ("GitHub Token", f"GITHUB_TOKEN={GITHUB_TOKEN}", GITHUB_TOKEN),
        ("Slack Token", f"SLACK_BOT_TOKEN={SLACK_2PART}", SLACK_2PART),
        ("Slack Token", f"SLACK_BOT_TOKEN={SLACK_3PART}", SLACK_3PART),
        ("Google Cloud API Key", f"GCP_API_KEY={GCP_API_KEY}", GCP_API_KEY),
        ("Stripe Secret Key", f"STRIPE_SECRET_KEY={STRIPE_KEY}", STRIPE_KEY),
        ("Passport MRZ", MRZ, MRZ),
    ]
)
def test_token_is_detected_and_masked(make_cli, share, write_file, capsys, category, line, raw_token):
    write_file(share / "secrets.txt", line + "\n")

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    matches = [f for f in cli.findings if f["category"] == category]
    assert len(matches) == 1, f"{category} was not reported"

    finding = matches[0]
    assert finding["severity"] == ("HIGH" if category == "Passport MRZ" else "CRITICAL")
    assert finding["score_r"] > 0
    assert raw_token not in finding["masked_evidence"], "raw token leaked into evidence"


@pytest.mark.parametrize("filename", ["server.pem", "server.key", "id_ed25519.key"])
def test_key_files_are_read_as_text(make_cli, share, filename, capsys):
    """A .pem/.key file is plain text; skipping the extension skips the banner detector."""
    body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB"
    (share / filename).write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" + body + "\n-----END OPENSSH PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    keys = [f for f in cli.findings if f["category"] == "Private Key"]
    assert len(keys) == 1, f"{filename} was not scanned"
    assert keys[0]["severity"] == "CRITICAL"
    assert body not in keys[0]["masked_evidence"], "key body leaked into evidence"


def test_passport_mrz_masking_hides_every_character():
    masked = mask_secret("passport_mrz", MRZ)
    assert masked == f"[PASSPORT MRZ: {len(MRZ)} characters redacted]"
    assert "ERIKSSON" not in masked


def test_mrz_inside_a_pdf_text_layer_is_detected(make_cli, share):
    """PDF documents run through the same identifier rules as text files."""
    (share / "passport.pdf").write_bytes(build_pdf(["PASSPORT", MRZ]))

    cli = make_cli()
    cli.run_audit()

    assert [f["category"] for f in cli.findings] == ["Passport MRZ"]


def test_wordlist_is_the_complete_bip39_dictionary():
    assert len(BIP39_WORDLIST) == 2048
    assert {"abandon", "zebra", "zero", "zone", "zoo", "void"} <= BIP39_WORDLIST


def test_phrase_using_words_outside_the_previous_subset_is_detected(
    make_cli, share, write_file, capsys
):
    # Words deep in the alphabet were missing from the old 250-word sample.
    phrase_words = sorted(BIP39_WORDLIST)[1500:1512]
    write_file(share / "seed.txt", "recovery phrase: " + " ".join(phrase_words) + "\n")

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    seeds = [f for f in cli.findings if f["category"] == "Crypto Seed Phrase"]
    assert len(seeds) == 1
    assert "12-WORD SEED PHRASE" in seeds[0]["masked_evidence"]
    assert phrase_words[1] not in seeds[0]["masked_evidence"]


def test_24_word_phrase_is_detected(make_cli, share, write_file, capsys):
    phrase_words = sorted(BIP39_WORDLIST)[:24]
    write_file(share / "seed24.txt", " ".join(phrase_words) + "\n")

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    seeds = [f for f in cli.findings if f["category"] == "Crypto Seed Phrase"]
    assert len(seeds) == 1, "a 24-word mnemonic must be one finding, not two 12-word matches"
    assert "24-WORD SEED PHRASE" in seeds[0]["masked_evidence"]


def test_incomplete_phrase_is_not_reported(make_cli, share, write_file, capsys):
    phrase_words = sorted(BIP39_WORDLIST)[:11]
    write_file(share / "short.txt", " ".join(phrase_words) + "\n")

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    assert cli.findings == []


def test_phrase_broken_by_a_non_dictionary_word_is_not_reported(
    make_cli, share, write_file, capsys
):
    phrase_words = sorted(BIP39_WORDLIST)[:12]
    write_file(share / "broken.txt", " ".join(phrase_words[:6]) + " zzzznotaword " + " ".join(phrase_words[6:]) + "\n")

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    assert cli.findings == []


def test_database_uri_password_with_at_sign_never_reaches_evidence(
    make_cli, share, vault, write_file, capsys
):
    password = "p@ssw0rd"
    write_file(
        share / ".env",
        f"DATABASE_URL=postgres://app_user:{password}@10.0.0.7:5432/prod\n",
    )

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    db_findings = [f for f in cli.findings if f["category"] == "Database URI"]
    assert len(db_findings) == 1
    assert (
        db_findings[0]["masked_evidence"]
        == "postgres://app_user:********@10.0.0.7:5432/prod"
    )

    reports = "\n".join(
        path.read_text(encoding="utf-8") for path in (vault / "Reports").glob("*")
    )
    for haystack in (json.dumps(cli.findings), reports):
        assert password not in haystack
        assert "ssw0rd" not in haystack


def test_valid_iban_is_reported(make_cli, share, write_file, capsys):
    write_file(share / "accounts.csv", "name,iban\nJane,DE89370400440532013000\n")

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    assert [f["category"] for f in cli.findings] == ["Financial Record (IBAN)"]


def test_iban_lookalike_failing_mod97_is_not_reported(make_cli, share, write_file, capsys):
    write_file(share / "accounts.csv", "name,iban\nJane,DE89370400440532013001\n")

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    assert cli.findings == [], "structural match without a valid checksum is noise, not a finding"


def test_slack_patterns_cover_legacy_and_modern_shapes():
    assert PATTERNS["slack_token"].fullmatch(SLACK_2PART)
    assert PATTERNS["slack_token"].fullmatch(SLACK_3PART)
    assert not PATTERNS["slack_token"].fullmatch("xoxb-not-a-token")
