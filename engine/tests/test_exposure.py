"""Exposure derivation: the context multipliers follow measured access, not a constant.

`R = S × (1 + α + β)` only means something if α and β describe who can really
reach the file. These tests pin that behaviour: a readable file behind a `0700`
directory is owner-only, a `0600` file in a `0777` directory is private, and an
explicit operator flag wins over both.
"""

import subprocess
import sys

import pytest

from rules import ExposureResolver


def chmod_tree(*pairs):
    for path, mode in pairs:
        path.chmod(mode)


def secret_file(root, name=".env"):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("OPENAI_API_KEY=sk-live-aaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", encoding="utf-8")
    return path


class TestDerivedExposure:
    def test_owner_only_tree_is_private(self, tmp_path):
        root = tmp_path / "Shared"
        path = secret_file(root / "app")
        chmod_tree((root, 0o700), (root / "app", 0o700), (path, 0o600))

        exposure = ExposureResolver(root).for_path(path)

        assert (exposure.shared, exposure.public) == (False, False)
        assert "owner-only" in exposure.evidence

    def test_group_readable_file_in_group_traversable_dirs_is_shared_only(self, tmp_path):
        root = tmp_path / "Shared"
        path = secret_file(root / "team")
        chmod_tree((root, 0o750), (root / "team", 0o750), (path, 0o640))

        exposure = ExposureResolver(root).for_path(path)

        assert (exposure.shared, exposure.public) == (True, False)
        assert "group users only" in exposure.evidence

    def test_world_readable_file_in_world_traversable_dirs_is_public(self, tmp_path):
        root = tmp_path / "Shared"
        path = secret_file(root / "public")
        chmod_tree((root, 0o755), (root / "public", 0o755), (path, 0o644))

        exposure = ExposureResolver(root).for_path(path)

        assert (exposure.shared, exposure.public) == (True, True)
        assert "group and other users" in exposure.evidence

    def test_readable_file_behind_private_directory_is_not_exposed(self, tmp_path):
        """Traversal is half the exposure: 0644 inside 0700 is still unreachable."""
        root = tmp_path / "Shared"
        path = secret_file(root / "private")
        chmod_tree((root, 0o755), (root / "private", 0o700), (path, 0o644))

        exposure = ExposureResolver(root).for_path(path)

        assert (exposure.shared, exposure.public) == (False, False)

    def test_private_file_in_public_directory_is_not_exposed(self, tmp_path):
        root = tmp_path / "Shared"
        path = secret_file(root / "open")
        chmod_tree((root, 0o777), (root / "open", 0o777), (path, 0o600))

        exposure = ExposureResolver(root).for_path(path)

        assert (exposure.shared, exposure.public) == (False, False)

    def test_unreadable_metadata_fails_closed(self, tmp_path):
        root = tmp_path / "Shared"
        root.mkdir()
        root.chmod(0o700)

        exposure = ExposureResolver(root).for_path(root / "vanished.env")

        assert (exposure.shared, exposure.public) == (True, True)
        assert "assuming exposed" in exposure.evidence

    def test_permissions_above_the_audited_root_are_ignored(self, tmp_path):
        """The volume mount's own mode must not leak into the share's score."""
        parent = tmp_path / "volume"
        root = parent / "Shared"
        path = secret_file(root / "app")
        chmod_tree((parent, 0o777), (root, 0o700), (root / "app", 0o700), (path, 0o600))

        exposure = ExposureResolver(root).for_path(path)

        assert (exposure.shared, exposure.public) == (False, False)


class TestOverrides:
    def test_flags_override_detected_exposure(self, tmp_path):
        root = tmp_path / "Shared"
        path = secret_file(root / "open")
        chmod_tree((root, 0o777), (root / "open", 0o777), (path, 0o644))

        exposure = ExposureResolver(root, shared=False, public=False).for_path(path)

        assert (exposure.shared, exposure.public) == (False, False)
        assert "--no-shared" in exposure.evidence and "--no-public" in exposure.evidence

    def test_flags_can_pin_exposure_on_a_private_tree(self, tmp_path):
        root = tmp_path / "Shared"
        path = secret_file(root / "app")
        chmod_tree((root, 0o700), (root / "app", 0o700), (path, 0o600))

        exposure = ExposureResolver(root, shared=True, public=True).for_path(path)

        assert (exposure.shared, exposure.public) == (True, True)

    def test_source_reports_where_the_multipliers_came_from(self, tmp_path):
        root = tmp_path / "Shared"
        root.mkdir()

        assert ExposureResolver(root).source == "derived"
        assert ExposureResolver(root, shared=True).source == "mixed"
        assert ExposureResolver(root, shared=True, public=True).source == "explicit"


class TestScoringIntegration:
    def test_private_file_scores_without_context_multipliers(self, make_cli, tmp_path):
        root = tmp_path / "Shared"
        path = secret_file(root / "app")
        chmod_tree((root, 0o700), (root / "app", 0o700), (path, 0o600))

        cli = make_cli(target=root, vault_path=tmp_path / "Vault")
        cli.run_audit()

        assert cli.findings and cli.findings[0]["severity"] == "CRITICAL"
        assert cli.findings[0]["score_r"] == 5.0

    def test_exposed_file_scores_with_both_multipliers(self, make_cli, tmp_path):
        root = tmp_path / "Shared"
        path = secret_file(root / "open")
        chmod_tree((root, 0o755), (root / "open", 0o755), (path, 0o644))

        cli = make_cli(target=root, vault_path=tmp_path / "Vault")
        cli.run_audit()

        assert cli.findings[0]["score_r"] == 11.25

    def test_saved_state_records_how_exposure_was_established(self, make_cli, tmp_path):
        import json

        root = tmp_path / "Shared"
        path = secret_file(root / "app")
        chmod_tree((root, 0o700), (root / "app", 0o700), (path, 0o600))

        cli = make_cli(target=root, vault_path=tmp_path / "Vault")
        cli.run_audit()

        state = json.loads(cli.state_path.read_text(encoding="utf-8"))
        assert state["is_shared"] is False and state["is_public"] is False
        assert state["exposure"]["source"] == "derived"
        assert "owner-only" in state["exposure"]["root_evidence"]


def run_cli(engine_dir, *args):
    return subprocess.run(
        [sys.executable, str(engine_dir / "sentry_cli.py"), *args],
        cwd=str(engine_dir),
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.mark.parametrize(
    "flags, root_mode, file_mode, expected_score, expected_source",
    [
        (("--no-shared", "--no-public"), 0o755, 0o644, 5.0, "explicit"),
        (("--shared", "--public"), 0o700, 0o600, 11.25, "explicit"),
        ((), 0o755, 0o644, 11.25, "derived"),
        ((), 0o700, 0o600, 5.0, "derived"),
    ],
)
def test_cli_flags_and_detection_agree(
    engine_dir, tmp_path, flags, root_mode, file_mode, expected_score, expected_source
):
    import json

    root = tmp_path / "Shared"
    path = secret_file(root / "app")
    chmod_tree((root, root_mode), (root / "app", root_mode), (path, file_mode))
    vault = tmp_path / "Vault"

    result = run_cli(engine_dir, "--target", str(root), "--vault", str(vault), *flags)
    assert result.returncode == 0, result.stdout + result.stderr

    state_path = sorted((vault / "Reports").glob("sentry-findings-*.json"))[-1]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert [finding["score_r"] for finding in state["findings"]] == [expected_score]
    assert state["exposure"]["source"] == expected_source
