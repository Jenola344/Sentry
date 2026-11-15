/**
 * Built-in realistic UGREEN AI NAS file dataset
 * Simulates /volume1/Shared with multi-user developer, financial, and backup files.
 */

export interface VirtualFile {
  path: string;
  name: string;
  size: number;
  type: 'text' | 'pdf' | 'image' | 'zip' | 'corrupt';
  content: string;
  isEncrypted?: boolean;
}

export const SAMPLE_NAS_FIXTURES: VirtualFile[] = [
  {
    path: '/volume1/Shared/Projects/app1/.env',
    name: '.env',
    size: 142,
    type: 'text',
    content: `# Production Environment Configuration
NODE_ENV=production
PORT=8080
OPENAI_API_KEY=sk-live-TESTING993848194810284729184810
DATABASE_URL=postgres://app_user:V3ryS3cur3P@ssw0rd!@127.0.0.1:5432/app_db`
  },
  {
    path: '/volume1/Shared/Projects/app1/package-lock.json',
    name: 'package-lock.json',
    size: 420,
    type: 'text',
    content: `{
  "name": "enterprise-portal",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/axios": {
      "integrity": "sha512-v3b5N0fG3K9A3X9Y4Z1bC9D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F2A1B0C9D8E7F=="
    }
  }
}`
  },
  {
    path: '/volume1/Shared/Projects/app1/index.js',
    name: 'index.js',
    size: 89,
    type: 'text',
    content: `console.log("Starting server on port", process.env.PORT || 8080);`
  },
  {
    path: '/volume1/Shared/Projects/app2/.env',
    name: '.env',
    size: 156,
    type: 'text',
    content: `# Staging Cloud Deploy
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
REGION=us-west-2`
  },
  {
    path: '/volume1/Shared/Backups/crypto_wallet_recovery.txt',
    name: 'crypto_wallet_recovery.txt',
    size: 210,
    type: 'text',
    content: `METAMASK ETHEREUM WALLET SEED PHRASE BACKUP
Word Count: 12
Words:
abandon ability able about above absent absorb abstract absurd abuse access accident

DO NOT SHARE!`
  },
  {
    path: '/volume1/Shared/Finance/payroll_2026.csv',
    name: 'payroll_2026.csv',
    size: 245,
    type: 'text',
    content: `EmployeeID,Name,SSN,Department,GrossPay,NetPay,IBAN
E104,Jane Doe,123-45-6789,Engineering,$9500.00,$7100.00,DE89370400440532013000
E105,John Smith,987-65-4321,Security,$10200.00,$7800.00,FR7630006000011234567890189`
  },
  {
    path: '/volume1/Shared/Documents/Bank_Statement_Jan2026.pdf',
    name: 'Bank_Statement_Jan2026.pdf',
    size: 48920,
    type: 'pdf',
    content: `UGREEN PRIVATE WEALTH STATEMENT
Account Holder: Alexander Vance
Account Balance: $482,910.00 USD
Routing Number: 021000021
Wire Transfer ID: UGR-88921-NYC`
  },
  {
    path: '/volume1/Shared/Documents/corrupt_doc.pdf',
    name: 'corrupt_doc.pdf',
    size: 0,
    type: 'corrupt',
    content: ``
  },
  {
    path: '/volume1/Shared/Archives/encrypted_keys.zip',
    name: 'encrypted_keys.zip',
    size: 1024,
    type: 'zip',
    isEncrypted: true,
    content: `[PKZIP_ENCRYPTED_HEADER_FLAG_0x0001]`
  },
  {
    path: '/volume1/Shared/Photos/payment_card_scan.png',
    name: 'payment_card_scan.png',
    size: 89420,
    type: 'image',
    content: `OCR Extracted Text:
VISA CORPORATE
4111 2222 3333 4444
VALID THRU: 11/28
CARDHOLDER: ALEXANDER VANCE`
  },
  {
    path: '/volume1/Shared/README.md',
    name: 'README.md',
    size: 65,
    type: 'text',
    content: `# Engineering Shared Storage
Welcome to team shared storage.`
  }
];
