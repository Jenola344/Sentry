"""Quarantine execution: one move and one manifest row per file."""

from support import DB_URI, OPENAI_KEY


def _finding(file_path, finding_id="FIND-001"):
    return {
        "id": finding_id,
        "severity": "CRITICAL",
        "score_r": 11.25,
        "category": "OpenAI API Key",
        "file": str(file_path),
        "masked_evidence": "sk-l****aaaa",
        "action": "Immediate Quarantine",
    }


def test_two_findings_in_one_file_yield_one_manifest_row(
    make_cli, share, write_file, manifest_rows, capsys
):
    write_file(share / "app" / ".env", f"OPENAI_API_KEY={OPENAI_KEY}\nDATABASE_URL={DB_URI}\n")

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    finding_ids = [f["id"] for f in cli.findings]
    assert len(finding_ids) == 2

    assert cli._execute_quarantine(finding_ids) is True

    manifests = list(cli.vault_path.glob("Quarantine_*/quarantine-manifest.md"))
    assert len(manifests) == 1

    rows = manifest_rows(manifests[0])
    assert len(rows) == 1, "two findings in one file must produce exactly one manifest row"

    row_ids = [i.strip() for i in rows[0].group("ids").split(",")]
    assert row_ids == finding_ids

    vaulted = list(cli.vault_path.glob("Quarantine_*/app/.env"))
    assert len(vaulted) == 1
    assert not (share / "app" / ".env").exists()

    manifest_text = manifests[0].read_text(encoding="utf-8")
    assert "- **Findings Approved:** 2" in manifest_text
    assert "- **Files Quarantined:** 1" in manifest_text


def test_separate_files_get_separate_rows(make_cli, share, write_file, manifest_rows, capsys):
    write_file(share / "a" / ".env", f"OPENAI_API_KEY={OPENAI_KEY}\n")
    write_file(share / "b" / ".env", "OPENAI_API_KEY=sk-live-bbbbbbbbbbbbbbbbbbbbbbbbbbbb\n")

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    assert cli._execute_quarantine([f["id"] for f in cli.findings]) is True

    manifest = next(cli.vault_path.glob("Quarantine_*/quarantine-manifest.md"))
    rows = manifest_rows(manifest)
    assert len(rows) == 2
    assert {row.group("orig").rsplit("/", 2)[-2] for row in rows} == {"a", "b"}


def test_only_approved_files_move(make_cli, share, write_file, capsys):
    write_file(share / "a" / ".env", f"OPENAI_API_KEY={OPENAI_KEY}\n")
    write_file(share / "b" / ".env", "OPENAI_API_KEY=sk-live-bbbbbbbbbbbbbbbbbbbbbbbbbbbb\n")

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()

    target_id = next(f["id"] for f in cli.findings if f["file"].endswith("/a/.env"))
    assert cli._execute_quarantine([target_id]) is True

    assert not (share / "a" / ".env").exists()
    assert (share / "b" / ".env").exists()


def test_file_outside_the_audited_root_is_refused(make_cli, tmp_path, write_file, capsys):
    outside = write_file(tmp_path / "elsewhere" / "secret.txt", f"OPENAI_API_KEY={OPENAI_KEY}\n")

    cli = make_cli()
    cli.findings = [_finding(outside)]

    assert cli._execute_quarantine(["FIND-001"]) is False
    assert outside.exists(), "a file outside the audited root must never be moved"
    assert "outside the audited root" in capsys.readouterr().out


def test_missing_source_is_reported_as_a_failure(make_cli, tmp_path, capsys):
    cli = make_cli()
    cli.findings = [_finding(tmp_path / "Shared" / "gone.env")]

    assert cli._execute_quarantine(["FIND-001"]) is False
    assert "no longer exists" in capsys.readouterr().out

    # A manifest is still written so the run leaves a usable audit trail.
    manifest = next(cli.vault_path.glob("Quarantine_*/quarantine-manifest.md"))
    assert "- **Files Quarantined:** 0" in manifest.read_text(encoding="utf-8")


def test_quarantine_preserves_relative_directory_tree(make_cli, share, write_file, capsys):
    write_file(share / "Projects" / "app1" / ".env", f"OPENAI_API_KEY={OPENAI_KEY}\n")
    write_file(share / "Projects" / "app2" / ".env", "OPENAI_API_KEY=sk-live-bbbbbbbbbbbbbbbbbbbbbbbbbbbb\n")

    cli = make_cli()
    cli.run_audit()
    capsys.readouterr()
    assert cli._execute_quarantine([f["id"] for f in cli.findings]) is True

    assert list(cli.vault_path.glob("Quarantine_*/Projects/app1/.env"))
    assert list(cli.vault_path.glob("Quarantine_*/Projects/app2/.env"))
