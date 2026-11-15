"""Rollback: checksum verification, conflict handling and idempotency."""

import hashlib
from pathlib import Path

from support import OPENAI_KEY
from sentry_cli import rollback_manifest


def _quarantine_one_file(make_cli, share, write_file, capsys, name=".env"):
    write_file(share / name, f"OPENAI_API_KEY={OPENAI_KEY}\n")
    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()
    assert cli._execute_quarantine([f["id"] for f in cli.findings]) is True
    manifest = next(cli.vault_path.glob("Quarantine_*/quarantine-manifest.md"))
    vaulted = next(cli.vault_path.glob(f"Quarantine_*/{name}"))
    return cli, manifest, vaulted


def test_rollback_restores_a_verified_file(make_cli, share, write_file, capsys):
    original_content = f"OPENAI_API_KEY={OPENAI_KEY}\n"
    cli, manifest, vaulted = _quarantine_one_file(make_cli, share, write_file, capsys)
    assert not (share / ".env").exists()

    assert rollback_manifest(manifest) is True

    restored = share / ".env"
    assert restored.read_text(encoding="utf-8") == original_content
    assert not vaulted.exists()
    assert "`RESTORED`" in manifest.read_text(encoding="utf-8")


def test_tampered_vault_file_is_not_restored(make_cli, share, write_file, capsys):
    cli, manifest, vaulted = _quarantine_one_file(make_cli, share, write_file, capsys)
    with open(vaulted, "a", encoding="utf-8") as vf:
        vf.write("\n# tampered\n")

    assert rollback_manifest(manifest) is False

    assert not (share / ".env").exists(), "a file failing its checksum must not be restored"
    assert vaulted.exists(), "the tampered copy stays in the vault for investigation"
    text = manifest.read_text(encoding="utf-8")
    assert "INTEGRITY_FAILED" in text
    assert "QUARANTINED" not in text


def test_conflicting_original_path_blocks_restore(make_cli, share, write_file, capsys):
    cli, manifest, vaulted = _quarantine_one_file(make_cli, share, write_file, capsys)
    (share / ".env").write_text("someone else's newer file\n", encoding="utf-8")

    assert rollback_manifest(manifest) is False

    assert (share / ".env").read_text(encoding="utf-8") == "someone else's newer file\n"
    assert vaulted.exists()
    assert "RESTORE_CONFLICT" in manifest.read_text(encoding="utf-8")


def test_replay_after_rollback_is_a_noop(make_cli, share, write_file, capsys):
    cli, manifest, _ = _quarantine_one_file(make_cli, share, write_file, capsys)

    assert rollback_manifest(manifest) is True
    assert rollback_manifest(manifest) is True

    assert (share / ".env").exists()


def test_missing_manifest_is_an_error(tmp_path):
    assert rollback_manifest(tmp_path / "nope.md") is False


def test_legacy_single_id_manifest_still_parses(make_cli, share, write_file, tmp_path, capsys):
    """Manifests written before multi-finding rows existed must keep working."""
    original = write_file(share / ".env", f"OPENAI_API_KEY={OPENAI_KEY}\n")
    payload = original.read_bytes()
    vaulted = tmp_path / "Vault" / "Quarantine_2026-01-01" / ".env"
    vaulted.parent.mkdir(parents=True)
    vaulted.write_bytes(payload)
    original.unlink()

    legacy_manifest = vaulted.parent / "quarantine-manifest.md"
    legacy_manifest.write_text(
        "# Sentry Quarantine Manifest\n\n"
        "| Finding ID | SHA-256 Checksum | Original Path | Vault Path | Status |\n"
        "| :--- | :--- | :--- | :--- | :--- |\n"
        f"| `FIND-001` | `{hashlib.sha256(payload).hexdigest()}` | `{original}` "
        f"| `{vaulted}` | `QUARANTINED` |\n",
        encoding="utf-8"
    )

    assert rollback_manifest(legacy_manifest) is True
    assert original.read_bytes() == payload


def test_path_with_pipe_character_round_trips(make_cli, share, write_file, capsys, manifest_rows):
    cli, manifest, vaulted = _quarantine_one_file(make_cli, share, write_file, capsys, name="we|ird.env")

    rows = manifest_rows(manifest)
    assert len(rows) == 1, "a pipe inside the path must not split the manifest row"
    assert rows[0].group("orig").endswith("we|ird.env")
    assert rows[0].group("vault").endswith("we|ird.env")

    assert rollback_manifest(manifest) is True
    assert (share / "we|ird.env").exists()
