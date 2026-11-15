# Sentry Detection Taxonomy & Pattern Reference

> **Companion Specification to [SKILL.md](../SKILL.md)**  
> **Skill:** `sentry` (UGREEN AI NAS Zero-Egress Auditor)  
> **Scope:** Comprehensive pattern catalog, regular expressions, algorithmic validators, and suppression rules.

---

## 1. Detection Engine Architecture

The Sentry detection engine operates as a four-pass deterministic state machine designed to minimize disk I/O and processor load on the UGREEN AI NAS while maintaining high recall and precision across heterogenous file collections.

```mermaid
flowchart TD
    File["Discovered File"] --> P1{"Pass 1: Resource Guard<br/>ug-filesystem"}
    P1 -- "Size > 50MB" --> SkipSize["Skip: Recorded as OVERSIZED"]
    P1 -- "Media Container (.mp4, .mkv...)" --> SkipMedia["Skip: STREAMING_MEDIA"]
    P1 -- "Lockfile (package-lock.json...)" --> WhiteLock["Whitelist: Suppress Hash Warnings"]
    P1 -- "Candidate File" --> RouteType{"MIME / Extension Check"}
    
    RouteType -- "Text / Code / Config" --> P2["Pass 2: Text & Secrets<br/>ug-document extract"]
    RouteType -- "Office / PDF / Sheet" --> P3["Pass 3: Structured Docs<br/>ug-document extract"]
    RouteType -- "Image / Screenshot" --> P4Cond{"scan_depth == deep?"}
    
    P4Cond -- "Yes" --> P4["Pass 4: Image Text & Metadata<br/>embedded text / EXIF"]
    P4Cond -- "No" --> EndPass["Skip: Scan Depth Standard"]
    
    P2 --> Entropy["Shannon Entropy & Proximity Filter"]
    P3 --> DocValidate["Format & Luhn / MRZ Validators"]
    P4 --> ImgValidate["Embedded-text & Metadata Validation"]
    
    Entropy --> Match{"Pattern Match?"}
    DocValidate --> Match
    ImgValidate --> Match
    
    Match -- "Yes" --> RecordFinding["Generate Finding ID & Mask Evidence"]
    Match -- "No" --> Clean["Mark Clean"]
```

---

## 2. Pass 1 — Inventory & Resource Guard

### File Categorization Matrix

| Category | File Extensions | Action | Justification |
| :--- | :--- | :--- | :--- |
| **Configuration & Code** | `.env*`, `.pem`, `.key`, `.p12`, `.json`, `.yaml`, `.yml`, `.txt`, `.md`, `.csv`, `.log`, `.sql`, `.xml`, `.conf`, `.ini` | **Inspect in Pass 2** | Primary source of developer credentials, API tokens, and connection strings. |
| **Structured Documents** | `.pdf`, `.docx`, `.xlsx`, `.csv`, `.odt`, `.ods`, `.rtf` | **Inspect in Pass 3** | Common carrier of tax forms, bank statements, identity cards, and payroll exports. |
| **Visual Media** | `.png`, `.jpg`, `.jpeg`, `.webp` | **Inspect in Pass 4 (Deep)** | Embedded text layers, annotations and EXIF GPS ride along with camera uploads, screenshots and scanned documents. Pixel OCR is delegated to `ug-photo` on UGOS and is not performed by the portable engine. |
| **Binary Executables** | `.exe`, `.dll`, `.so`, `.bin`, `.app`, `.dmg`, `.deb`, `.rpm` | **Skip** | Executable binaries lack structured secret context and risk triggering high false positives. |
| **Media Streams** | `.mp4`, `.mkv`, `.avi`, `.mov`, `.wmv`, `.flv`, `.webm`, `.mp3`, `.wav`, `.flac`, `.aac`, `.ogg`, `.m4a` | **Skip** | High volume, low probability of extractable text secrets; protects NAS disk pool I/O. |
| **Disk Images** | `.iso`, `.img`, `.vmdk`, `.qcow2`, `.vdi` | **Skip** | Monolithic container images exceed single-file processing budgets. |
| **Dependency Locks** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `composer.lock`, `Gemfile.lock` | **Whitelist / Suppress** | Contain hundreds of SHA-256/512 checksums that naive scanners mistake for active tokens. |

### Resource Safeguard Invariants
- **Maximum File Size Ceiling:** Exactly **52,428,800 bytes (50 MB)**. Files exceeding this threshold are bypassed and recorded in the audit log under `SKIPPED_OVERSIZED`.
- **Symlink Depth Limit:** Recursion stops at a directory depth of **16 levels** to avoid symlink loop traps across nested user folders.

---

## 3. Pass 2 — Text, Code & Configuration Secrets

### Secret Token Signatures & Regular Expressions

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                   PASS 2: CREDENTIAL PATTERN MATRIX                    │
 ├────────────────────────┬───────────────────────────────────────────────┤
 │ Secret Type            │ Canonical Regular Expression                  │
 ├────────────────────────┼───────────────────────────────────────────────┤
 │ OpenAI API Key         │ sk-(?:proj-|live-)?[a-zA-Z0-9_-]{32,64}       │
 │ AWS Access Key ID      │ (?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA │
 │                        │ |ANVA|ASIA)[A-Z0-9]{16}                       │
 │ AWS Secret Access Key  │ (?i)aws_secret_access_key\s*=\s*[a-zA-Z0-9/+= │
 │                        │ ]{40}                                         │
 │ GitHub Token (Classic) │ ghp_[a-zA-Z0-9]{36}                           │
 │ Slack Bot / User Token │ xox[baprs]-[0-9]{10,13}(?:-[0-9]{10,13})?-[a- │
 │                        │ zA-Z0-9]{24,32}                               │
 │ Google Cloud API Key   │ AIza[0-9A-Za-z\-_]{35}                        │
 │ Stripe Secret Key      │ (?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{24,99}    │
 │ Private Key Banners    │ -----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE │
 │                        │ KEY-----                                      │
 │ Database Connection    │ (?:postgres|postgresql|mongodb\+srv|mongodb   │
 │ Strings with Passwords │ |mysql):\/\/[^:\s]+:[^@\s]+@[^\/\s]+          │
 └────────────────────────┴───────────────────────────────────────────────┘
```

### BIP-39 Cryptocurrency Recovery Seed Phrases

BIP-39 mnemonic recovery phrases represent root access to cryptocurrency wallets. Sentry validates candidate word sequences against the official 2,048-word BIP-39 English dictionary:

- **Detection Rule:**
  - 12 or 24 consecutive dictionary words separated by whitespace.
  - Every candidate word is matched against the full **2,048-word English BIP-39 list**, shipped as `engine/bip39_english.txt` and loaded by `rules.py` (a short or missing list raises at import rather than silently degrading detection).
  - Runs are scanned to their end before a finding is emitted, so a 24-word mnemonic is reported once as a 24-word phrase instead of two overlapping 12-word matches.
  - Any non-dictionary token breaks the run. No proximity keyword is required: a bare mnemonic is still a mnemonic.
- **Severity Rating:** `CRITICAL` ($S = 5.0$).

---

## 4. Pass 3 — Structured Documents & Financial Records

Pass 3 processes `.pdf` and `.csv` files to uncover personal identity and banking records. PDF text layers also run through the Pass 2 credential/identifier rules, so a passport MRZ or API key embedded in a document is caught here. On UGOS, `ug-document` supplies extracted text for `.docx` and `.xlsx` as well; the portable engine does not parse those Office containers.

### Banking & Financial Regex Rules

#### 1. International Bank Account Numbers (IBAN)
- **Regex:** `\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b`
- **Validation:** Modulo-97 check ($ISO\ 7064$). Convert letters to numbers ($A=10 \dots Z=35$), move the first 4 characters to the end, and verify that the integer modulo 97 equals 1.
- **Severity:** `HIGH` ($S = 3.0$) if accompanied by account holder names or balances; otherwise `MEDIUM` ($S = 1.0$).

#### 2. SWIFT / BIC Codes
- **Regex:** `\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b`
- **Context Guard:** Only triggers when within 10 lines of `SWIFT`, `BIC`, `Bank`, or `Wire Transfer`.

#### 3. Payroll & Tax Ledgers
- Detects recurring tables containing `Gross Pay`, `Net Pay`, `Withholding`, `Federal Tax`, `Medicare`, or `Social Security`.
- **Severity:** `HIGH` ($S = 3.0$).

### Government Identification Patterns

#### 1. United States Social Security Number (SSN)
- **Regex:** `\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b`
- **Exclusion Filters:** Applies the SSA structural rules in the regex itself (area `000`/`666`/`9xx`, group `00`, serial `0000`). Sequential placeholder values are not special-cased, so `123-45-6789` is still reported.
- **Severity:** `HIGH` ($S = 3.0$).

#### 2. Passport Machine Readable Zone (MRZ - ICAO Doc 9303)
- **Type 3 (Passports) line 1:** `P<[A-Z]{3}[A-Z0-9<]{39}`
- **Masking:** the line is never reproduced; evidence shows `[PASSPORT MRZ: <n> characters redacted]`.
- **Severity:** `HIGH` ($S = 3.0$).


---

## 5. Pass 4 — Image Text & Metadata Audit (`ug-photo`)

When `scan_depth=deep`, image files are inspected in two layers.

### Layer 1 — Embedded text (portable engine, `engine/image_text.py`, no OCR)

Text already stored inside the file is extracted without any optical recognition:

| Container | Carriers |
| :--- | :--- |
| **PNG** | `tEXt`, `zTXt`, `iTXt` chunks |
| **JPEG** | `COM` comments, EXIF `ImageDescription` / `Software` / `Artist` / `UserComment` |

The extracted text is then run through the Pass 2 detectors (cloud keys, private-key banners, seed phrases) and the validators below. Findings are labelled `(<category>) (image text)` so they are distinguishable from text-file hits.

### Layer 2 — Exposure metadata

An EXIF GPS IFD pointer is reported as `MEDIUM` ($S = 1.0$) with the coordinates withheld: a photographed document on shared storage also reveals where it was taken. The engine never returns coordinate values, only their presence.

### Payment Card Verification (Luhn Algorithm)

Sentry validates 13–19 digit sequences found in embedded image text:

```python
def luhn_checksum_valid(number_str: str) -> bool:
    """Verifies candidate card number against ISO/IEC 7812 Luhn checksum."""
    clean_digits = [int(c) for c in number_str if c.isdigit()]
    if not (13 <= len(clean_digits) <= 19):
        return False
    checksum = 0
    reverse_digits = clean_digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0
```

- **Major Card Brand Prefixes:**
  - Visa: `^4[0-9]{12}(?:[0-9]{3})?$`
  - Mastercard: `^(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}$`
  - American Express: `^3[47][0-9]{13}$`
  - Discover: `^6(?:011|5[0-9]{2})[0-9]{12}$`
- **Expiration Date Correlation:** Not evaluated by the portable engine. Expiry or CVV context may be supplied by `ug-photo` OCR blocks on device, but its absence does not lower the severity of a Luhn-valid number.
- **Severity:** A Luhn-valid 13–19 digit number found in shared storage scores `HIGH` ($S = 3.0$).

### Delegated Visual Classification (`ug-photo`, device only)
On UGOS, `ug-photo analyze --type id_card,document` checks visual aspect ratios and returns layout tags. The portable engine does not perform this step, because it requires the device NPU vision models:
- `layout: passport_spread`
- `layout: drivers_license_front`
- `layout: credit_card_front`

On the device, a layout match with confidence $\ge 0.75$ is classified as `HIGH` ($S = 3.0$).

---

## 6. Shannon Entropy & False Positive Suppression

To avoid alerting on random hashes or GUIDs, Sentry applies Shannon Entropy analysis to candidate secret strings:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where:
- $n$ is the number of distinct characters in the candidate string.
- $P(x_i)$ is the empirical probability of character $x_i$ appearing in the string.

### Entropy Decision Boundaries
- **Natural Language Prose:** $3.0 \le H < 4.2$ bits/character $\rightarrow$ **Suppress** (False Positive).
- **Standard UUIDs & Monotonic Sequences:** $H < 3.8$ bits/character $\rightarrow$ **Suppress**.
- **Cryptographic Keys & High-Entropy Tokens:** $H \ge 4.5$ bits/character $\rightarrow$ **Trigger Deep Regex Inspection**.

### Lockfile Suppression Mechanics
Package lockfiles contain valid Base64 and Hexadecimal integrity hashes (e.g., `sha512-...`). Sentry suppresses integrity checks if the file matches the whitelist pattern:
`/(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|composer\.lock)$/`

This suppression ensures zero false positives during routine developer workspace audits.
