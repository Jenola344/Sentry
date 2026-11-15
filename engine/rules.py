"""
Sentry Detection Rules & Masking Engine
---------------------------------------
Modular detection taxonomy, entropy calculation, format validation,
and zero-leak evidence masking for UGREEN AI NAS security auditing.
"""

import re
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# BIP-39 English mnemonic dictionary (2,048 words). Loaded from the canonical
# wordlist shipped beside this module so detection never relies on a partial sample.
BIP39_WORDLIST_PATH = Path(__file__).with_name("bip39_english.txt")


def load_bip39_wordlist(path: Path = BIP39_WORDLIST_PATH) -> frozenset:
    """Loads the BIP-39 English wordlist, failing loudly if it is missing or short."""
    try:
        raw_words = path.read_text(encoding="utf-8").split()
    except OSError as exc:
        raise RuntimeError(f"BIP-39 wordlist unavailable at {path}: {exc}") from exc

    wordlist = frozenset(word.strip().lower() for word in raw_words if word.strip())
    if len(wordlist) != 2048:
        raise RuntimeError(
            f"BIP-39 wordlist at {path} must hold 2,048 unique words, found {len(wordlist)}"
        )
    return wordlist


BIP39_WORDLIST = load_bip39_wordlist()

def find_bip39_phrases(text: str) -> List[str]:
    """Returns BIP-39 candidate phrases, preferring 24-word runs.

    Runs are flushed only when they end, so a 24-word mnemonic is reported once
    as a 24-word phrase instead of being split into two 12-word matches.
    """
    phrases: List[str] = []
    run: List[str] = []

    def flush() -> None:
        while len(run) >= 24:
            phrases.append(" ".join(run[:24]))
            del run[:24]
        if len(run) >= 12:
            phrases.append(" ".join(run[:12]))
        # Always reset: a short fragment must not bridge the token that broke the run.
        run.clear()

    for raw_word in text.split():
        word = raw_word.lower()
        if word.isalpha() and word in BIP39_WORDLIST:
            run.append(word)
        else:
            flush()

    flush()
    return phrases

# Whitelist dependency lockfiles that contain legitimate hashes
WHITELIST_LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.lock", "poetry.lock", "composer.lock", "Gemfile.lock"
}

# Streaming media file extensions skipped to preserve NAS resource limits
MEDIA_EXTENSIONS = {
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".mp3", ".wav", ".flac", ".aac", ".ogg", ".iso", ".img",
    ".vmdk", ".qcow2", ".vdi"
}

# Supported text & code extensions for Pass 2
TEXT_EXTENSIONS = {
    ".env", ".txt", ".md", ".json", ".yaml", ".yml", ".sql",
    ".conf", ".ini", ".log", ".xml", ".js", ".ts", ".py",
    ".sh", ".toml", ".cfg"
}

# Regular expressions for credentials and sensitive data
PATTERNS = {
    "openai_api_key": re.compile(r"sk-(?:proj-|live-)?[a-zA-Z0-9_-]{24,64}"),
    "aws_access_key": re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?"),
    "github_token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"),
    "slack_token": re.compile(r"xox[baprs]-[0-9]{10,13}(?:-[0-9]{10,13})?-[a-zA-Z0-9]{24,32}"),
    "gcp_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "stripe_key": re.compile(r"\b(?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{24,99}\b"),
    "database_uri": re.compile(r"(?:postgres|postgresql|mongodb\+srv|mongodb|mysql):\/\/[^:\s]+:[^@\s]+@[^\/\s]+(?:\/[^\s]*)?"),
    "private_key_header": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "us_ssn": re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "iban": re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b"),
    "passport_mrz": re.compile(r"P<[A-Z]{3}[A-Z0-9<]{39}")
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def luhn_checksum_valid(card_str: str) -> bool:
    """Validates candidate credit/debit card numbers with ISO/IEC 7812 Luhn algorithm."""
    digits = [int(c) for c in card_str if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def iban_checksum_valid(iban_str: str) -> bool:
    """Validates an IBAN using the standard Modulo-97 algorithm."""
    clean = re.sub(r"\s+", "", iban_str).upper()
    if len(clean) < 15 or len(clean) > 34:
        return False
    rearranged = clean[4:] + clean[:4]
    numeric_str = ""
    for ch in rearranged:
        if ch.isalpha():
            numeric_str += str(ord(ch) - 55)
        else:
            numeric_str += ch
    try:
        return int(numeric_str) % 97 == 1
    except ValueError:
        return False


def mask_database_uri(uri: str) -> str:
    """Redacts the whole userinfo password of a connection string.

    The URI is split on the *last* ``@`` (the only legal credentials/host
    separator) so a raw ``@``, ``/`` or ``:`` inside the password cannot shift
    the split point and leak the tail of the secret.
    """
    scheme, sep, rest = uri.partition("://")
    if not sep:
        return "****REDACTED****"

    # The authority must be split after the last '@' and before any later '/',
    # otherwise a '/' inside the password is mistaken for the path separator.
    credentials_end = rest.rfind("@")
    if credentials_end == -1:
        return "****REDACTED****"

    userinfo = rest[:credentials_end]
    host, slash, path = rest[credentials_end + 1:].partition("/")

    user, colon, _password = userinfo.partition(":")
    masked_userinfo = f"{user}:********" if colon else user
    return f"{scheme}://{masked_userinfo}@{host}{slash}{path}"


def mask_secret(secret_type: str, raw_val: str) -> str:
    """
    Deterministic zero-leak evidence masking standard.
    Never persists or outputs raw credentials.
    """
    val = raw_val.strip()
    if secret_type in ("api_key", "token", "password"):
        if len(val) <= 10:
            return val[:2] + "****" + val[-2:]
        return val[:4] + "****" + val[-4:]
    
    elif secret_type == "bip39_seed":
        words = val.split()
        first_word = words[0] if words else "phrase"
        return f"[{len(words)}-WORD SEED PHRASE starting with \"{first_word}...\"]"
    
    elif secret_type == "payment_card":
        digits = [c for c in val if c.isdigit()]
        if len(digits) >= 12:
            first4 = "".join(digits[:4])
            last4 = "".join(digits[-4:])
            return f"{first4}-****-****-{last4}"
        return "****-****-****-****"
    
    elif secret_type == "ssn":
        digits = [c for c in val if c.isdigit()]
        last4 = "".join(digits[-4:]) if len(digits) >= 4 else "XXXX"
        return f"***-**-{last4}"
    
    elif secret_type == "iban":
        country = val[:2].upper()
        last4 = val[-4:]
        return f"{country}**-****-****-****-{last4}"
    
    elif secret_type == "passport_mrz":
        return f"[PASSPORT MRZ: {len(val)} characters redacted]"

    elif secret_type == "database_uri":
        return mask_database_uri(val)
    
    elif secret_type == "private_key":
        return "[BEGIN PRIVATE KEY: Cryptographic Body Redacted]"
        
    return "****REDACTED****"


@dataclass(frozen=True)
class Exposure:
    """Who can actually reach one path, derived from POSIX bits and directory reachability."""

    shared: bool
    public: bool
    evidence: str


class ExposureResolver:
    """Derives the context multipliers from real access, not from a hardcoded worst case.

    A path counts as reachable only when the file *and* every directory between it
    and the audited root grant the matching access bit: a readable file inside a
    ``0700`` directory is still owner-only, and a ``0600`` file inside a ``0777``
    directory is still private. Unreadable metadata fails closed (treated as
    exposed) so an optimistic default can never under-report exposure.
    """

    def __init__(self, root: Path, shared: Optional[bool] = None, public: Optional[bool] = None):
        self.root = Path(root).resolve()
        self._override_shared = shared
        self._override_public = public
        self._dir_cache: Dict[Path, Tuple[bool, bool]] = {}

    @property
    def source(self) -> str:
        """Whether the multipliers came from the filesystem, from flags, or both."""
        overrides = (self._override_shared is not None, self._override_public is not None)
        if all(overrides):
            return "explicit"
        if any(overrides):
            return "mixed"
        return "derived"

    def _dir_reach(self, directory: Path) -> Tuple[bool, bool]:
        """Returns (group-traversable, other-traversable) for a directory and its ancestors.

        Traversal stops at the audited root: permissions above the share belong to
        the volume mount, not to the share being audited.
        """
        directory = Path(directory).resolve()
        cached = self._dir_cache.get(directory)
        if cached is not None:
            return cached

        try:
            mode = directory.stat().st_mode & 0o777
        except OSError:
            return (True, True)  # fail closed

        group_ok = bool(mode & 0o010)
        other_ok = bool(mode & 0o001)

        at_base = directory == self.root or self.root not in directory.parents
        if at_base:
            result = (group_ok, other_ok)
        else:
            parent_group, parent_other = self._dir_reach(directory.parent)
            result = (group_ok and parent_group, other_ok and parent_other)

        self._dir_cache[directory] = result
        return result

    def for_path(self, path: Path) -> Exposure:
        """Resolves the exposure of one file, honouring explicit operator overrides."""
        path = Path(path)
        try:
            mode = path.stat().st_mode & 0o777
        except OSError:
            shared, public = True, True
            evidence = "metadata unreadable — assuming exposed"
        else:
            group_traversable, other_traversable = self._dir_reach(path.parent)
            shared = bool(group_traversable and mode & 0o040)
            public = bool(other_traversable and mode & 0o004)
            if public:
                evidence = f"mode {mode:04o} readable by group and other users"
            elif shared:
                evidence = f"mode {mode:04o} readable by group users only"
            else:
                evidence = f"mode {mode:04o} owner-only (no group/other reachability)"

        notes = []
        if self._override_shared is not None:
            shared = self._override_shared
            notes.append(f"α forced by --{'shared' if shared else 'no-shared'}")
        if self._override_public is not None:
            public = self._override_public
            notes.append(f"β forced by --{'public' if public else 'no-public'}")
        if notes:
            evidence = f"{evidence}; {'; '.join(notes)}"

        return Exposure(shared=shared, public=public, evidence=evidence)

    def for_root(self) -> Exposure:
        """Exposure of the audited root itself, used for the audit header and saved state."""
        return self.for_path(self.root)


def compute_risk_score(base_severity: str, is_shared: bool, is_public: bool) -> Tuple[float, float, float, float]:
    """
    Computes context-aware risk score:
    R = S * (1 + alpha_multi + beta_public)
    """
    severity_map = {"CRITICAL": 5.0, "HIGH": 3.0, "MEDIUM": 1.0}
    s = severity_map.get(base_severity, 1.0)
    alpha = 0.50 if is_shared else 0.00
    beta = 0.75 if is_public else 0.00
    r = s * (1.0 + alpha + beta)
    return s, alpha, beta, round(r, 2)
