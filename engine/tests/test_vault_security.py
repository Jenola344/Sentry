"""Vault hardening: owner-only tree, vault outside the share, verified moves.

Quarantining a secret must not publish it. Three properties are pinned here:
the vault tree is `0700`, a vault inside the audited root is refused outright,
and the checksum recorded in the manifest is verified *after* the move so a file
edited mid-quarantine cannot be filed under a hash it no longer matches.
"""

import hashlib
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from support import OPENAI_KEY


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def secret_share(tmp_path: Path, write_file, name: str = "app") -> Path:
    share = tmp_path / "Shared"
    write_file(share / name / ".env", f"OPENAI_API_KEY={OPENAI_KEY}\n")
    return share


def quarantined_dir(vault: Path) -> Path:
    return next(vault.glob("Quarantine_*"))


class TestOwnerOnlyTree:
    def test_vault_session_and_parents_are_owner_only(self, make_cli, tmp_path, write_file):
        share = secret_share(tmp_path, write_file)
        vault = tmp_path / "Vault"

        cli = make_cli(target=share, vault_path=vault)
        cli.run_audit()
        assert cli.prompt_quarantine_gate("ALL CRITICAL") is True

        session = quarantined_dir(vault)
        for directory in (vault, session, session / "app"):
            assert mode_of(directory) == 0o700, f"{directory} is {oct(mode_of(directory))}"
        assert (session / "app" / ".env").exists()

    def test_an_existing_world_readable_vault_is_tightened(self, make_cli, share, tmp_path):
        vault = tmp_path / "Vault"
        vault.mkdir()
        vault.chmod(0o755)

        make_cli(target=share, vault_path=vault)

        assert mode_of(vault) == 0o700

    def test_audit_creates_the_vault_owner_only_before_any_quarantine(
        self, make_cli, tmp_path, write_file
    ):
        share = secret_share(tmp_path, write_file)
        vault = tmp_path / "Vault"

        make_cli(target=share, vault_path=vault)

        assert vault.is_dir()
        assert mode_of(vault) == 0o700


class TestVaultLocation:
    def test_vault_inside_the_audited_root_is_refused(self, make_cli, tmp_path, write_file):
        share = secret_share(tmp_path, write_file)

        with pytest.raises(ValueError) as excinfo:
            make_cli(target=share, vault_path=share / "Vault")

        assert "outside the audited root" in str(excinfo.value)
        assert not (share / "Vault").exists()

    def test_nested_vault_below_the_root_is_refused(self, make_cli, tmp_path, write_file):
        share = secret_share(tmp_path, write_file)

        with pytest.raises(ValueError):
            make_cli(target=share, vault_path=share / "private" / "Vault")

    def test_vault_equal_to_the_root_is_refused(self, make_cli, tmp_path, write_file):
        share = secret_share(tmp_path, write_file)

        with pytest.raises(ValueError):
            make_cli(target=share, vault_path=share)

    def test_sibling_vault_is_accepted(self, make_cli, tmp_path, write_file):
        share = secret_share(tmp_path, write_file)

        cli = make_cli(target=share, vault_path=tmp_path / "Private_Security_Vault")

        assert cli.vault_path == (tmp_path / "Private_Security_Vault").resolve()


class TestVerifiedMove:
    def test_manifest_hash_matches_the_quarantined_copy(self, make_cli, tmp_path, write_file):
        share = secret_share(tmp_path, write_file)
        vault = tmp_path / "Vault"

        cli = make_cli(target=share, vault_path=vault)
        cli.run_audit()
        assert cli.prompt_quarantine_gate("ALL CRITICAL") is True

        stored = quarantined_dir(vault) / "app" / ".env"
        digest = hashlib.sha256(stored.read_bytes()).hexdigest()
        manifest = (quarantined_dir(vault) / "quarantine-manifest.md").read_text(encoding="utf-8")
        assert digest in manifest

    def test_file_changed_during_the_move_is_returned_not_filed(
        self, make_cli, tmp_path, write_file, monkeypatch, capsys
    ):
        """A checksum taken before the move is only trustworthy if it is re-checked after.

        The file that moved is the file that comes back: the point is that it is
        neither filed under a hash it no longer matches nor lost.
        """
        import sentry_cli

        share = secret_share(tmp_path, write_file)
        vault = tmp_path / "Vault"

        real_move = sentry_cli.shutil.move

        def tampering_move(src, dst, *args, **kwargs):
            result = real_move(src, dst, *args, **kwargs)
            if "Quarantine_" in str(dst):
                Path(dst).write_text("tampered in transit", encoding="utf-8")
            return result

        monkeypatch.setattr(sentry_cli.shutil, "move", tampering_move)

        cli = make_cli(target=share, vault_path=vault)
        cli.run_audit()
        approved = cli.prompt_quarantine_gate("ALL CRITICAL")

        assert approved is False
        restored = share / "app" / ".env"
        assert restored.exists(), "the file must be returned to its original path"
        assert restored.read_text(encoding="utf-8") == "tampered in transit"
        assert not (quarantined_dir(vault) / "app" / ".env").exists()

        manifest = (quarantined_dir(vault) / "quarantine-manifest.md").read_text(encoding="utf-8")
        assert "tampered in transit" not in manifest
        assert manifest.count("| `FIND-") == 0

        output = capsys.readouterr().out
        assert "checksum mismatch after the move" in output
        assert "RETURNED" in output


def run_cli(engine_dir: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(engine_dir / "sentry_cli.py"), *args],
        cwd=str(engine_dir),
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_cli_refuses_a_vault_inside_the_share(engine_dir, tmp_path, write_file):
    share = secret_share(tmp_path, write_file)

    result = run_cli(
        engine_dir,
        "--target", str(share),
        "--vault", str(share / "Vault"),
        "--approve", "ALL",
    )

    assert result.returncode == 1
    assert "outside the audited root" in result.stdout
    assert (share / "app" / ".env").exists()
    assert not (share / "Vault").exists()


def test_cli_quarantines_into_an_owner_only_vault(engine_dir, tmp_path, write_file):
    share = secret_share(tmp_path, write_file)
    vault = tmp_path / "Vault"

    assert run_cli(engine_dir, "--target", str(share), "--vault", str(vault)).returncode == 0
    gate = run_cli(engine_dir, "--target", str(share), "--vault", str(vault), "--approve", "ALL CRITICAL")

    assert gate.returncode == 0, gate.stdout + gate.stderr
    assert mode_of(vault) == 0o700
    assert mode_of(quarantined_dir(vault)) == 0o700
    assert not (share / "app" / ".env").exists()
