import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { LOG_PATH } from './paths.ts';

type LogLevel = 'info' | 'warn' | 'error';

// Field names whose values are written as "[REDACTED]" on disk regardless of
// the caller's redaction discipline at the emitter site. Vikunja is shared-
// key with no per-user vendor token; only the gate JWT and standard auth
// header names are sensitive.
const REDACTED_FIELDS = new Set([
  'jwt',
  'idToken',
  'refreshToken',
  'id_token',
  'refresh_token',
  'authorization',
  'Authorization',
  'cf-access-jwt-assertion',
]);

let directoryReady = false;

async function ensureDir(): Promise<void> {
  if (directoryReady) return;
  await mkdir(dirname(LOG_PATH), { recursive: true, mode: 0o700 });
  directoryReady = true;
}

function redact(fields: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    out[k] = REDACTED_FIELDS.has(k) ? '[REDACTED]' : v;
  }
  return out;
}

// GOTCHA: see GOTCHAS.md §"Stdout must be pristine". Stdout is the MCP
// protocol channel — writing to it corrupts framing and breaks the host
// silently. All log output goes to file (or stderr as a last-resort
// fallback). NEVER call console.log from this module or anywhere
// reachable from the request path.
export async function log(
  level: LogLevel,
  msg: string,
  fields: Record<string, unknown> = {},
): Promise<void> {
  const line = JSON.stringify({
    t: new Date().toISOString(),
    level,
    msg,
    ...redact(fields),
  }) + '\n';
  try {
    await ensureDir();
    await appendFile(LOG_PATH, line, { mode: 0o600 });
  } catch {
    // Last-ditch fallback so the bridge doesn't crash on logging failure —
    // stderr is inherited by the host so the operator can still read it.
    process.stderr.write(line);
  }
}
