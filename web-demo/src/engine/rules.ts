/**
 * Sentry Web Engine — Rules, Regexes & Secret Masking
 * Mirrors the native UGOS Sentry Skill taxonomy.
 */

export const BIP39_WORDLIST = new Set([
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
  "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army",
  "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
  "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma",
  "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit",
  "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid",
  "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby",
  "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo",
  "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic"
]);

export const WHITELIST_LOCKFILES = new Set([
  "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
  "Cargo.lock", "poetry.lock", "composer.lock", "Gemfile.lock"
]);

export const MEDIA_EXTENSIONS = new Set([
  ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
  ".mp3", ".wav", ".flac", ".aac", ".ogg", ".iso", ".img",
  ".vmdk", ".qcow2", ".vdi"
]);

export function luhnValid(cardStr: string): boolean {
  const digits = cardStr.replace(/\D/g, '').split('').map(Number);
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  digits.reverse().forEach((d, idx) => {
    if (idx % 2 === 1) {
      const doubled = d * 2;
      sum += doubled > 9 ? doubled - 9 : doubled;
    } else {
      sum += d;
    }
  });
  return sum % 10 === 0;
}

export function ibanValid(ibanStr: string): boolean {
  const clean = ibanStr.replace(/\s+/g, '').toUpperCase();
  if (clean.length < 15 || clean.length > 34) return false;
  const rearranged = clean.slice(4) + clean.slice(0, 4);
  let numStr = '';
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    if (code >= 65 && code <= 90) {
      numStr += (code - 55).toString();
    } else {
      numStr += rearranged[i];
    }
  }
  // BigInt modulo 97
  try {
    return BigInt(numStr) % 97n === 1n;
  } catch {
    return false;
  }
}

export function maskSecret(secretType: string, rawVal: string): string {
  const val = rawVal.trim();
  switch (secretType) {
    case 'api_key':
    case 'token':
    case 'password':
      if (val.length <= 10) return val.slice(0, 2) + '****' + val.slice(-2);
      return val.slice(0, 4) + '****' + val.slice(-4);
    
    case 'bip39_seed': {
      const words = val.split(/\s+/);
      const first = words[0] || 'seed';
      return `[${words.length}-WORD SEED PHRASE starting with "${first}..."]`;
    }

    case 'payment_card': {
      const digits = val.replace(/\D/g, '');
      if (digits.length >= 12) {
        return `${digits.slice(0, 4)}-****-****-${digits.slice(-4)}`;
      }
      return '****-****-****-****';
    }

    case 'ssn': {
      const digits = val.replace(/\D/g, '');
      const last4 = digits.length >= 4 ? digits.slice(-4) : 'XXXX';
      return `***-**-${last4}`;
    }

    case 'iban': {
      const clean = val.replace(/\s+/g, '').toUpperCase();
      const country = clean.slice(0, 2);
      const last4 = clean.slice(-4);
      return `${country}**-****-****-****-${last4}`;
    }

    case 'database_uri':
      return val.replace(/:([^/@:\s]+)@/, ':********@');

    case 'private_key':
      return '[BEGIN PRIVATE KEY: Cryptographic Body Redacted]';

    default:
      return '****REDACTED****';
  }
}

export function computeRiskScore(
  baseSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM',
  isShared: boolean,
  isPublic: boolean
): { s: number; alpha: number; beta: number; r: number } {
  const sMap = { CRITICAL: 5.0, HIGH: 3.0, MEDIUM: 1.0 };
  const s = sMap[baseSeverity] || 1.0;
  const alpha = isShared ? 0.50 : 0.00;
  const beta = isPublic ? 0.75 : 0.00;
  const r = parseFloat((s * (1.0 + alpha + beta)).toFixed(2));
  return { s, alpha, beta, r };
}
