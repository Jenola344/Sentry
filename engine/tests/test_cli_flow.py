"""End-to-end CLI behaviour: saved audit state and the confirmation gate."""

import subprocess
import sys
from pathlib import Path

from support import OPENAI_KEY


def run_cli(engine_dir: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(engine_dir / "sentry_cli.py"), *args],
        cwd=str(engine_dir),
        capture_output=True,
        text=True,
        timeout=120
    )


def test_approval_confirms_the_saved_audit_without_rescanning(
    engine_dir, tmp_path, write_file
):
    share = tmp_path / "Shared"
    vault = tmp_path / "Vault"
    write_file(share / "reviewed" / ".env", f"OPENAI_API_KEY={OPENAI_KEY}\n")

    audit = run_cli(engine_dir, "--target", str(share), "--vault", str(vault))
    assert audit.returncode == 0, audit.stdout + audit.stderr
    assert "Audit state saved" in audit.stdout

    # A new critical file appears after the operator's review finished.
    write_file(share / "unreviewed" / ".env", "OPENAI_API_KEY=sk-live-bbbbbbbbbbbbbbbbbbbbbbbbbbbb\n")

    gate = run_cli(engine_dir, "--target", str(share), "--vault", str(vault),
                   "--approve", "ALL CRITICAL")
    assert gate.returncode == 0, gate.stdout + gate.stderr
    assert "no filesystem scan performed" in gate.stdout

    assert not (share / "reviewed" / ".env").exists()
    assert (share / "unreviewed" / ".env").exists(), "the gate must not act on a fresh scan"


def test_documented_all_critical_grammar_quarantines(engine_dir, tmp_path, write_file):
    share = tmp_path / "Shared"
    vault = tmp_path / "Vault"
    write_file(share / "app" / ".env", f"OPENAI_API_KEY={OPENAI_KEY}\n")

    assert run_cli(engine_dir, "--target", str(share), "--vault", str(vault)).returncode == 0
    gate = run_cli(engine_dir, "--target", str(share), "--vault", str(vault),
                   "--approve", "ALL CRITICAL")

    assert gate.returncode == 0
    assert "QUARANTINED" in gate.stdout
    assert not (share / "app" / ".env").exists()


def test_unknown_command_moves_nothing(engine_dir, tmp_path, write_file):
    share = tmp_path / "Shared"
    vault = tmp_path / "Vault"
    write_file(share / ".env", f"OPENAI_API_KEY={OPENAI_KEY}\n")

    assert run_cli(engine_dir, "--target", str(share), "--vault", str(vault)).returncode == 0
    gate = run_cli(engine_dir, "--target", str(share), "--vault", str(vault),
                   "--approve", "FIND-404")

    assert gate.returncode == 0
    assert "matched no finding" in gate.stdout
    assert (share / ".env").exists()


def test_approval_without_a_saved_audit_fails(engine_dir, tmp_path):
    share = tmp_path / "Shared"
    share.mkdir()

    result = run_cli(engine_dir, "--target", str(share), "--vault", str(tmp_path / "Empty"),
                     "--approve", "ALL CRITICAL")

    assert result.returncode == 1
    assert "no saved audit state" in result.stdout


def test_audit_approve_rollback_roundtrip(engine_dir, tmp_path, write_file):
    share = tmp_path / "Shared"
    vault = tmp_path / "Vault"
    target = write_file(share / "app" / ".env", f"OPENAI_API_KEY={OPENAI_KEY}\n")
    original = target.read_text(encoding="utf-8")

    assert run_cli(engine_dir, "--target", str(share), "--vault", str(vault)).returncode == 0
    assert run_cli(engine_dir, "--target", str(share), "--vault", str(vault),
                   "--approve", "ALL CRITICAL").returncode == 0
    assert not target.exists()

    manifest = next(vault.glob("Quarantine_*/quarantine-manifest.md"))
    rollback = run_cli(engine_dir, "--action", "rollback", "--manifest", str(manifest))

    assert rollback.returncode == 0, rollback.stdout + rollback.stderr
    assert target.read_text(encoding="utf-8") == original
