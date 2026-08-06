#!/usr/bin/env node
// Encrypts the resume template into assets/js/resume-data.js.
// The published payload is AES-256-GCM ciphertext; the resume text is
// never readable from the public repo.
//
// Usage:
//   node tools/encrypt-resume.mjs            # passphrase from $RESUME_PASSPHRASE
//   node tools/encrypt-resume.mjs "my phrase" # or passed on the command line
//   node tools/encrypt-resume.mjs --save      # also writes passphrase to .passphrase (gitignored)
//
// Re-run this every time you edit resume-src/resume-template.html.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { pbkdf2Sync, createCipheriv, randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

const ITERATIONS = 200000;
const KEY_LEN = 32;
const SALT_LEN = 16;
const IV_LEN = 12;

let passphrase = process.argv[2] || process.env.RESUME_PASSPHRASE;
const wantSave = process.argv.includes('--save');

if (!passphrase) {
  console.error('No passphrase given. Pass it as an argument or set $RESUME_PASSPHRASE.');
  process.exit(1);
}
if (passphrase.length < 8) {
  console.error('Passphrase too short — use at least 8 characters.');
  process.exit(1);
}

const source = readFileSync(join(root, 'resume-src', 'resume-template.html'), 'utf8');
const logo = readFileSync(join(root, 'assets', 'img', 'logo_crop.png'));

const html = source.replace(
  'src="./logo_crop.png"',
  `src="data:image/png;base64,${logo.toString('base64')}"`,
);

const salt = randomBytes(SALT_LEN);
const iv = randomBytes(IV_LEN);
const key = pbkdf2Sync(passphrase, salt, ITERATIONS, KEY_LEN, 'sha256');
const cipher = createCipheriv('aes-256-gcm', key, iv);
const data = Buffer.concat([cipher.update(html, 'utf8'), cipher.final()]);
const tag = cipher.getAuthTag();

const payload = {
  v: 1,
  iterations: ITERATIONS,
  salt: salt.toString('base64'),
  iv: iv.toString('base64'),
  tag: tag.toString('base64'),
  data: data.toString('base64'),
};

const outDir = join(root, 'assets', 'js');
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, 'resume-data.js'), `window.RESUME_SECRET = ${JSON.stringify(payload)};\n`);

if (wantSave) {
  writeFileSync(join(root, '.passphrase'), passphrase + '\n');
}

console.log(`Encrypted resume written to assets/js/resume-data.js (${data.length} bytes).`);
