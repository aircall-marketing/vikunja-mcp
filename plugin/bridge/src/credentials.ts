import { spawnSync } from 'node:child_process';
import { createCipheriv, createDecipheriv, randomBytes, hkdfSync } from 'node:crypto';

// Vikunja is shared-key — no vendor refresh token to persist. This module
// exists only so gate.ts can reuse the same machine-bound AES-256-GCM
// envelope for its own credential file (gate.json). The threat model is:
// defeats "copy gate.json to another machine / restore from a backup image"
// by binding the key to hardware + the logged-in user. Does NOT defeat
// malware running as the same user on the same machine.

const ENVELOPE_VERSION = 0x01;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

// HKDF salt + info strings — unique per MCP so two bridges installed side-
// by-side derive different keys. Bumping the version suffix is a deliberate
// kill-switch — invalidates every existing credential file on disk.
const HKDF_SALT = Buffer.from('aircall-vikunja-mcp-salt-v1', 'utf-8');
const HKDF_INFO = Buffer.from('aircall-vikunja-mcp-creds-v1', 'utf-8');

let _keyCache: Buffer | null = null;

function deriveKey(): Buffer {
  if (_keyCache) return _keyCache;

  const uid = process.getuid?.();
  if (uid === undefined) {
    throw new Error('process.getuid() unavailable — credentials encryption requires POSIX');
  }

  // NOTE: macOS only. For Linux/Windows pilots, replace with the platform's
  // equivalent stable machine ID (machine-id on Linux, MachineGuid on
  // Windows registry).
  const ioreg = spawnSync('/usr/sbin/ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], {
    encoding: 'utf-8',
  });
  if (ioreg.status !== 0) {
    throw new Error(`ioreg failed: ${ioreg.stderr ?? '(no stderr)'}`);
  }
  const match = ioreg.stdout.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
  if (!match) {
    throw new Error('IOPlatformUUID not found in ioreg output');
  }
  const machineUuid = match[1];

  const ikm = Buffer.from(`${machineUuid}:${uid}`, 'utf-8');
  _keyCache = Buffer.from(hkdfSync('sha256', ikm, HKDF_SALT, HKDF_INFO, KEY_LEN));
  return _keyCache;
}

export function encrypt(plaintext: string): Buffer {
  const key = deriveKey();
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([ENVELOPE_VERSION]), nonce, ciphertext, authTag]);
}

export function decrypt(envelope: Buffer): string {
  if (envelope.length < 1 + NONCE_LEN + TAG_LEN) {
    throw new Error('envelope too short');
  }
  if (envelope[0] !== ENVELOPE_VERSION) {
    throw new Error(`unsupported envelope version: 0x${envelope[0].toString(16)}`);
  }
  const key = deriveKey();
  const nonce = envelope.subarray(1, 1 + NONCE_LEN);
  const ciphertext = envelope.subarray(1 + NONCE_LEN, envelope.length - TAG_LEN);
  const authTag = envelope.subarray(envelope.length - TAG_LEN);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf-8');
}
