"""Detection-rule helpers: masking, format validation and risk scoring."""

import pytest

from rules import (
    PATTERNS,
    calculate_shannon_entropy,
    compute_risk_score,
    iban_checksum_valid,
    luhn_checksum_valid,
    mask_secret
)


class TestZeroLeakMasking:
    @pytest.mark.parametrize(
        "secret",
        [
            "sk-live-9f8a32b01c4d9e8f7a6b5c4d3e2f1a0b",
            "ghp_0123456789abcdefghijklmnopqrstuvwx",
            "AKIAIOSFODNN7EXAMPLE",
        ]
    )
    def test_api_key_masking_keeps_only_edges(self, secret):
        masked = mask_secret("api_key", secret)
        assert masked == secret[:4] + "****" + secret[-4:]
        # The interior must not survive anywhere in the rendered evidence.
        assert secret[4:-4] not in masked

    def test_short_api_key_masks_all_but_two_chars(self):
        assert mask_secret("api_key", "abc1234567") == "ab****67"

    def test_seed_phrase_reports_word_count_and_first_word_only(self):
        phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        masked = mask_secret("bip39_seed", phrase)
        assert masked == '[12-WORD SEED PHRASE starting with "abandon..."]'
        assert "ability" not in masked

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("4111 2222 3333 4444", "4111-****-****-4444"),
            ("4111-2222-3333-4444", "4111-****-****-4444"),
        ]
    )
    def test_payment_card_masks_middle_digits(self, raw, expected):
        masked = mask_secret("payment_card", raw)
        assert masked == expected
        assert "22223333" not in masked.replace("-", "")

    def test_ssn_keeps_last_four(self):
        assert mask_secret("ssn", "123-45-6789") == "***-**-6789"

    def test_iban_keeps_country_and_last_four(self):
        assert mask_secret("iban", "DE89370400440532013000") == "DE**-****-****-****-3000"

    def test_database_uri_redacts_password_only(self):
        masked = mask_secret("database_uri", "postgres://admin:SuperSecret2026!@10.0.0.5:5432/corp")
        assert masked == "postgres://admin:********@10.0.0.5:5432/corp"
        assert "SuperSecret2026!" not in masked

    @pytest.mark.parametrize(
        "raw, expected, leak_fragments",
        [
            # An unescaped '@' in the password used to leave its tail in the
            # evidence (the masker stopped at the first '@').
            (
                "postgres://app:p@ssw0rd@db.internal:5432/prod",
                "postgres://app:********@db.internal:5432/prod",
                ["p@ss", "ssw0rd"],
            ),
            # '/' in the password stopped the old character class entirely.
            (
                "mongodb+srv://svc:pa/ss@word@cluster0.example.net/app",
                "mongodb+srv://svc:********@cluster0.example.net/app",
                ["pa/ss", "ss@word", "word"],
            ),
            # ':' inside the password must not be mistaken for the user separator.
            (
                "mysql://root:a:b@c@nas-db:3306/app",
                "mysql://root:********@nas-db:3306/app",
                ["a:b", "b@c"],
            ),
            # No path: the host must still be preserved and the password gone.
            (
                "postgresql://read_only:hunter2@10.1.1.9",
                "postgresql://read_only:********@10.1.1.9",
                ["hunter2"],
            ),
        ]
    )
    def test_database_uri_password_with_uri_delimiters_never_leaks(
        self, raw, expected, leak_fragments
    ):
        masked = mask_secret("database_uri", raw)

        assert masked == expected
        for fragment in leak_fragments:
            assert fragment not in masked

    def test_unparsable_database_uri_is_redacted_wholesale(self):
        assert mask_secret("database_uri", "not-a-uri") == "****REDACTED****"
        assert mask_secret("database_uri", "postgres://host/db") == "****REDACTED****"

    def test_private_key_body_is_never_rendered(self):
        masked = mask_secret("private_key", "-----BEGIN RSA PRIVATE KEY-----")
        assert masked == "[BEGIN PRIVATE KEY: Cryptographic Body Redacted]"

    def test_unknown_category_redacts_entirely(self):
        assert mask_secret("something_new", "value") == "****REDACTED****"


class TestRiskScore:
    @pytest.mark.parametrize(
        "severity, is_shared, is_public, expected_s, expected_alpha, expected_beta, expected_r",
        [
            ("CRITICAL", True, True, 5.0, 0.50, 0.75, 11.25),
            ("CRITICAL", True, False, 5.0, 0.50, 0.00, 7.50),
            ("CRITICAL", False, True, 5.0, 0.00, 0.75, 8.75),
            ("CRITICAL", False, False, 5.0, 0.00, 0.00, 5.00),
            ("HIGH", True, True, 3.0, 0.50, 0.75, 6.75),
            ("HIGH", True, False, 3.0, 0.50, 0.00, 4.50),
            ("HIGH", False, True, 3.0, 0.00, 0.75, 5.25),
            ("HIGH", False, False, 3.0, 0.00, 0.00, 3.00),
            ("MEDIUM", True, True, 1.0, 0.50, 0.75, 2.25),
            ("MEDIUM", False, False, 1.0, 0.00, 0.00, 1.00),
        ]
    )
    def test_context_multipliers(self, severity, is_shared, is_public,
                                 expected_s, expected_alpha, expected_beta, expected_r):
        s, alpha, beta, r = compute_risk_score(severity, is_shared, is_public)
        assert (s, alpha, beta, r) == (expected_s, expected_alpha, expected_beta, expected_r)

    def test_unknown_severity_falls_back_to_medium_weighting(self):
        assert compute_risk_score("UNKNOWN", False, False) == (1.0, 0.0, 0.0, 1.0)

    def test_maximum_composite_score_is_11_25(self):
        assert compute_risk_score("CRITICAL", True, True)[3] == 11.25


class TestFormatValidators:
    @pytest.mark.parametrize("card", ["4111111111111111", "5500005555555559", "378282246310005"])
    def test_valid_card_numbers(self, card):
        assert luhn_checksum_valid(card) is True

    @pytest.mark.parametrize("card", ["4111111111111112", "1234567890123", "4111"])
    def test_invalid_card_numbers(self, card):
        assert luhn_checksum_valid(card) is False

    def test_iban_mod97(self):
        assert iban_checksum_valid("DE89370400440532013000") is True
        assert iban_checksum_valid("FR7630006000011234567890189") is True
        assert iban_checksum_valid("DE89370400440532013001") is False

    @pytest.mark.parametrize("value, expected", [("", 0.0), ("aaaa", 0.0), ("ab", 1.0)])
    def test_shannon_entropy(self, value, expected):
        assert calculate_shannon_entropy(value) == pytest.approx(expected)


class TestPatterns:
    def test_openai_key_pattern_matches_live_and_project_keys(self):
        assert PATTERNS["openai_api_key"].search("OPENAI_API_KEY=sk-live-aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assert PATTERNS["openai_api_key"].search("sk-proj-bbbbbbbbbbbbbbbbbbbbbbbbbbbb")

    def test_aws_access_key_pattern_matches_only_key_shapes(self):
        assert PATTERNS["aws_access_key"].search("AKIAIOSFODNN7EXAMPLE")
        assert not PATTERNS["aws_access_key"].search("AKIA-not-a-key")

    def test_private_key_header_pattern(self):
        assert PATTERNS["private_key_header"].search("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert not PATTERNS["private_key_header"].search("-----BEGIN PUBLIC KEY-----")
