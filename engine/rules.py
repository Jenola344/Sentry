"""
Sentry Detection Rules & Masking Engine
---------------------------------------
Modular detection taxonomy, entropy calculation, format validation,
and zero-leak evidence masking for UGREEN AI NAS security auditing.
"""

import re
import math
from typing import Tuple, List, Optional

# Standard BIP-39 2048-word mnemonic dictionary excerpt (representative canonical sample)
BIP39_WORDLIST = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief"
}

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
    "slack_token": re.compile(r"xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]{24,32}"),
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
    
    elif secret_type == "database_uri":
        return re.sub(r":([^/@:\s]+)@", ":********@", val)
    
    elif secret_type == "private_key":
        return "[BEGIN PRIVATE KEY: Cryptographic Body Redacted]"
        
    return "****REDACTED****"


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
