"""The human confirmation grammar documented in README.md / SKILL.md."""

import pytest

from sentry_cli import normalize_finding_id, resolve_approval

FINDINGS = [
    {"id": "FIND-001", "severity": "CRITICAL"},
    {"id": "FIND-002", "severity": "CRITICAL"},
    {"id": "FIND-003", "severity": "HIGH"},
    {"id": "FIND-004", "severity": "MEDIUM"},
]


@pytest.mark.parametrize(
    "command, expected_ids",
    [
        ("ALL CRITICAL", ["FIND-001", "FIND-002"]),
        ("APPROVE ALL CRITICAL", ["FIND-001", "FIND-002"]),
        ("all critical", ["FIND-001", "FIND-002"]),
        ("ALL", ["FIND-001", "FIND-002", "FIND-003", "FIND-004"]),
        ("APPROVE ALL", ["FIND-001", "FIND-002", "FIND-003", "FIND-004"]),
        ("FIND-001, FIND-002", ["FIND-001", "FIND-002"]),
        ("APPROVE FIND-001,FIND-002", ["FIND-001", "FIND-002"]),
        ("APPROVE  FIND-003 ", ["FIND-003"]),
        ("find-4", ["FIND-004"]),
        ("FIND-002, FIND-002", ["FIND-002"]),
    ]
)
def test_documented_commands_are_accepted(command, expected_ids):
    decision, approved, unknown = resolve_approval(command, FINDINGS)
    assert decision == "approve"
    assert approved == expected_ids
    assert unknown == []


@pytest.mark.parametrize("command", ["ABORT", "abort", "CANCEL", "  cancel  "])
def test_abort_commands_move_nothing(command):
    decision, approved, unknown = resolve_approval(command, FINDINGS)
    assert (decision, approved, unknown) == ("abort", [], [])


@pytest.mark.parametrize("command", ["", "   ", "APPROVE", "GARBAGE", "ALL HIGH"])
def test_unrecognised_commands_are_rejected(command):
    decision, approved, unknown = resolve_approval(command, FINDINGS)
    assert decision == "unknown"
    assert approved == []


def test_unknown_finding_id_is_reported():
    decision, approved, unknown = resolve_approval("FIND-999", FINDINGS)
    assert decision == "unknown"
    assert approved == []
    assert unknown == ["FIND-999"]


def test_mixed_known_and_unknown_ids_do_not_partially_approve():
    decision, approved, unknown = resolve_approval("FIND-001, FIND-999", FINDINGS)
    assert decision == "unknown"
    assert approved == []
    assert unknown == ["FIND-999"]


def test_all_critical_with_no_critical_findings_is_not_an_approval():
    findings = [{"id": "FIND-001", "severity": "HIGH"}]
    decision, approved, unknown = resolve_approval("ALL CRITICAL", findings)
    assert decision == "approve"
    assert approved == []


@pytest.mark.parametrize(
    "token, expected",
    [
        ("FIND-001", "FIND-001"),
        ("find-001", "FIND-001"),
        ("FIND-1", "FIND-001"),
        ("FIND001", "FIND-001"),
        ("FIND-0001", "FIND-001"),
        ("FIND-42", "FIND-042"),
    ]
)
def test_finding_id_normalisation(token, expected):
    assert normalize_finding_id(token) == expected


@pytest.mark.parametrize("token", ["FIND-", "FIND-12345", "X", "001", ""])
def test_invalid_finding_ids_are_rejected(token):
    assert normalize_finding_id(token) is None
