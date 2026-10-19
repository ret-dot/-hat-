// Usage: npx tsx scripts/hash-password.ts 'my-password'
// Paste the output into the "passwordHash" field of a GT_USERS entry.
import { hashPassword } from '../src/api/auth.js';
const pw = process.argv[2];
if (!pw || pw.length < 12) { console.error('Provide a password of at least 12 characters'); process.exit(1); }
console.log(hashPassword(pw));