// Pluggable edge-gate auth.
//
// The "gate" is the perimeter that decides whether a request is allowed
// to reach the hosted MCP server at all. Storyblok is shared-key (no per-
// user vendor token), so the gate is the only auth layer the bridge
// performs.
//
// Two implementations live in this file:
//   - CFManagedOAuthGate: the production default — Cloudflare Access
//     self-hosted app with "Managed OAuth" enabled. The Access app
//     becomes an OAuth 2.0 authorization server. Discovery happens at
//     <app-domain>/.well-known/oauth-authorization-server. We use a
//     pre-registered public client_id (RFC 7591 registered once per
//     fleet, baked at build time) + PKCE; no client_secret. Bridge
//     opens browser to authorization_endpoint, captures code on a
//     loopback redirect, exchanges for access_token + refresh_token,
//     stores encrypted on disk, refreshes silently before expiry, and
//     applies the access token as `Authorization: Bearer ...` on every
//     upstream request.
//   - IAPGate: stub for a future migration to GCP HTTPS LB + IAP. Throws
//     not-implemented for now. The interface is identical so swapping is
//     a single env-var flip plus filling in the impl.
//
// Selection happens at build time via the GATE_MODE env var (config.ts).
// No runtime mode-switching — each compiled bridge is bound to one gate.

import { createServer, type Server } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir, chmod, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { URL, URLSearchParams } from 'node:url';
import {
  GATE_MODE,
  CF_ACCESS_TEAM_DOMAIN,
  CF_OAUTH_CLIENT_ID,
  CLOUD_RUN_URL,
  GATE_TOKEN_CACHE_MS,
} from './config.ts';
import { GATE_PATH } from './paths.ts';
import { encrypt, decrypt } from './credentials.ts';
import { log } from './log.ts';

// ─── Interface ────────────────────────────────────────────────────────

export interface PendingGateAuth {
  authUrl: string;
  onComplete: Promise<void>;
  cancel: () => void;
}

export interface GateAuth {
  applyHeaders(headers: Headers): Promise<void>;
  isReady(): Promise<boolean>;
  invalidate(): void;
  bootstrap(): Promise<PendingGateAuth>;
  clear(): Promise<void>;
}

// ─── On-disk envelope (shared between gate impls) ─────────────────────

interface StoredGateCreds {
  accessToken: string;
  refreshToken?: string;
  accessTokenExpiresAt: number;
  email?: string;
  savedAt: string;
  mode: 'cf-managed-oauth' | 'iap';
}

async function readGateCreds(): Promise<StoredGateCreds | null> {
  let raw: Buffer;
  try {
    raw = await readFile(GATE_PATH);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
  try {
    const parsed = JSON.parse(decrypt(raw)) as StoredGateCreds;
    if (parsed.mode !== GATE_MODE) {
      await log('warn', 'gate creds mode mismatch — discarding', {
        fileMode: parsed.mode,
        runtimeMode: GATE_MODE,
      });
      await unlink(GATE_PATH).catch(() => {});
      return null;
    }
    return parsed;
  } catch (err) {
    await log('warn', 'gate creds decrypt failed, deleting file', {
      error: (err as Error).message,
    });
    await unlink(GATE_PATH).catch(() => {});
    return null;
  }
}

async function writeGateCreds(creds: StoredGateCreds): Promise<void> {
  await mkdir(dirname(GATE_PATH), { recursive: true, mode: 0o700 });
  const envelope = encrypt(JSON.stringify(creds));
  await writeFile(GATE_PATH, envelope, { mode: 0o600 });
  await chmod(GATE_PATH, 0o600);
}

// ─── CF Managed OAuth impl ────────────────────────────────────────────

class CFManagedOAuthGate implements GateAuth {
  private cache: StoredGateCreds | null = null;
  private loaded = false;

  async applyHeaders(headers: Headers): Promise<void> {
    await this.ensureLoaded();
    const now = Date.now();
    if (!this.cache || this.cache.accessTokenExpiresAt <= now + 60_000) {
      if (this.cache?.refreshToken) {
        try {
          await this.refreshSilently();
        } catch (err) {
          await log('warn', 'gate refresh failed', {
            error: (err as Error).message,
          });
          this.cache = null;
          await unlink(GATE_PATH).catch(() => {});
          throw new GateNotReadyError('gate access token expired, refresh failed');
        }
      } else {
        throw new GateNotReadyError('no gate access token cached');
      }
    }
    headers.set('Authorization', `Bearer ${this.cache!.accessToken}`);
  }

  async isReady(): Promise<boolean> {
    await this.ensureLoaded();
    if (!this.cache) return false;
    if (this.cache.accessTokenExpiresAt > Date.now() + 60_000) return true;
    return Boolean(this.cache.refreshToken);
  }

  invalidate(): void {
    if (this.cache) this.cache.accessTokenExpiresAt = 0;
  }

  async clear(): Promise<void> {
    this.cache = null;
    this.loaded = true;
    await unlink(GATE_PATH).catch(() => {});
  }

  async bootstrap(): Promise<PendingGateAuth> {
    return startLoopbackOAuth(async (creds) => {
      this.cache = creds;
      this.loaded = true;
      await writeGateCreds(creds);
      await log('info', 'gate sign-in completed', { email: creds.email });
    });
  }

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return;
    this.cache = await readGateCreds();
    this.loaded = true;
  }

  private async refreshSilently(): Promise<void> {
    if (!this.cache?.refreshToken) {
      throw new Error('refreshSilently called without refresh_token');
    }
    const tokens = await callTokenEndpoint({
      grant_type: 'refresh_token',
      refresh_token: this.cache.refreshToken,
      client_id: CF_OAUTH_CLIENT_ID,
      resource: oauthResource(),
    });
    if (!tokens.access_token) throw new Error('refresh response missing access_token');
    const expiresAt = Date.now() + Math.min((tokens.expires_in ?? 3600) * 1000, GATE_TOKEN_CACHE_MS);
    const updated: StoredGateCreds = {
      ...this.cache,
      accessToken: tokens.access_token,
      accessTokenExpiresAt: expiresAt,
      refreshToken: tokens.refresh_token ?? this.cache.refreshToken,
      savedAt: new Date().toISOString(),
    };
    this.cache = updated;
    await writeGateCreds(updated);
  }
}

// ─── IAP impl (stub for future migration) ─────────────────────────────

class IAPGate implements GateAuth {
  // PHASE 2: implement using GCP IAP. Filling this in is the bulk of the
  // CF→IAP migration work — see plan.

  async applyHeaders(_headers: Headers): Promise<void> {
    throw new Error('IAPGate.applyHeaders not yet implemented (GATE_MODE=iap)');
  }
  async isReady(): Promise<boolean> {
    return false;
  }
  invalidate(): void {}
  async bootstrap(): Promise<PendingGateAuth> {
    throw new Error('IAPGate.bootstrap not yet implemented (GATE_MODE=iap)');
  }
  async clear(): Promise<void> {
    await unlink(GATE_PATH).catch(() => {});
  }
}

// ─── OAuth 2.0 PKCE flow against CF Managed OAuth ─────────────────────

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
  token_type?: string;
  error?: string;
  error_description?: string;
}

function teamBase(): string {
  return `https://${CF_ACCESS_TEAM_DOMAIN}.cloudflareaccess.com`;
}

function authorizationUrl(): string {
  return `${teamBase()}/cdn-cgi/access/oauth/authorization`;
}

function tokenUrl(): string {
  return `${teamBase()}/cdn-cgi/access/oauth/token`;
}

// RFC 8707 Resource Indicator — identifies which protected resource the
// access token will be used against. Cloudflare Managed OAuth uses this
// to bind the OAuth flow to a specific Access application; without it
// CF returns "Application is not an OIDC application" because the
// dynamically-registered client isn't tied to any single app.
//
// Imported from CLOUD_RUN_URL's origin so all per-MCP bridges share one
// resource URI (the whole mcp.trentmorris.dev domain), letting one
// sign-in gate every per-path MCP under the same Access app.
function oauthResource(): string {
  const u = new URL(CLOUD_RUN_URL);
  return `${u.protocol}//${u.host}`;
}

async function callTokenEndpoint(params: Record<string, string>): Promise<TokenResponse> {
  const body = new URLSearchParams(params);
  const res = await fetch(tokenUrl(), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  const json = (await res.json()) as TokenResponse;
  if (!res.ok || json.error) {
    throw new Error(
      `CF token endpoint: ${json.error ?? res.status} ${json.error_description ?? ''}`,
    );
  }
  return json;
}

function startLoopbackOAuth(
  onSuccess: (creds: StoredGateCreds) => Promise<void>,
): Promise<PendingGateAuth> {
  const state = randomBytes(16).toString('hex');
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  let resolveOnComplete!: () => void;
  let rejectOnComplete!: (err: Error) => void;
  const onComplete = new Promise<void>((resolve, reject) => {
    resolveOnComplete = resolve;
    rejectOnComplete = reject;
  });

  let redirectUri = '';
  let settled = false;
  const settle = (err: Error | null) => {
    if (settled) return;
    settled = true;
    if (err) rejectOnComplete(err);
    else resolveOnComplete();
  };

  const server: Server = createServer(async (req, res) => {
    if (!req.url) {
      res.statusCode = 400;
      res.end('missing url');
      return;
    }
    const u = new URL(req.url, 'http://127.0.0.1');
    const code = u.searchParams.get('code');
    const error = u.searchParams.get('error');
    const gotState = u.searchParams.get('state');

    if (error) {
      res.statusCode = 400;
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.end(errorHtml(`Cloudflare Access returned an error: ${escapeHtml(error)}`));
      settle(new Error(`gate sign-in error: ${error}`));
      return;
    }
    if (!code || gotState !== state) {
      res.statusCode = 400;
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.end(errorHtml('State mismatch or missing code. Restart sign-in from Claude.'));
      settle(new Error('missing code or state mismatch'));
      return;
    }

    try {
      const tokens = await callTokenEndpoint({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
        client_id: CF_OAUTH_CLIENT_ID,
        resource: oauthResource(),
      });
      if (!tokens.access_token) throw new Error('CF token response missing access_token');
      const expiresAt = Date.now() + Math.min((tokens.expires_in ?? 3600) * 1000, GATE_TOKEN_CACHE_MS);
      const email = extractEmail(tokens.id_token);
      const creds: StoredGateCreds = {
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        accessTokenExpiresAt: expiresAt,
        email,
        savedAt: new Date().toISOString(),
        mode: 'cf-managed-oauth',
      };
      await onSuccess(creds);

      res.statusCode = 200;
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.end(successHtml(email));
      settle(null);
    } catch (err) {
      const message = (err as Error).message;
      await log('error', 'gate token exchange failed', { error: message });
      res.statusCode = 500;
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.end(errorHtml(escapeHtml(message)));
      settle(err as Error);
    }
  });

  return new Promise<PendingGateAuth>((resolve, reject) => {
    // GOTCHA: Cloudflare Managed OAuth strict-matches the redirect URI
    // (port and all) against the registered client. RFC 8252 §7.3 says
    // loopback URIs should be port-wildcarded for native apps; CF
    // doesn't follow that. So we pin a fixed port that matches what
    // the client_id was registered with. If the port is in use on
    // the pilot's machine, surface a clear, actionable error — better
    // than the cryptic "Invalid redirect URL" CF would show otherwise.
    const FIXED_LOOPBACK_PORT = 47832;
    server.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        reject(
          new Error(
            `Port ${FIXED_LOOPBACK_PORT} is in use by another process on this Mac. ` +
              `Sign-in needs that exact port (Cloudflare Access requires it). ` +
              `Identify the conflicting process with: lsof -i :${FIXED_LOOPBACK_PORT}` +
              ` — close it and try signing in again.`,
          ),
        );
      } else {
        reject(err);
      }
    });
    server.listen(FIXED_LOOPBACK_PORT, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : -1;
      if (port < 0) {
        server.close();
        reject(new Error('loopback listener: address() returned no port'));
        return;
      }
      redirectUri = `http://127.0.0.1:${port}/callback`;
      const params = new URLSearchParams({
        client_id: CF_OAUTH_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        resource: oauthResource(),
      });
      const authUrl = `${authorizationUrl()}?${params.toString()}`;
      const cancel = () => {
        server.close();
        settle(new Error('cancelled'));
      };
      void onComplete.finally(() => server.close()).catch(() => {});
      resolve({ authUrl, onComplete, cancel });
    });
  });
}

// ─── Errors ───────────────────────────────────────────────────────────

export class GateNotReadyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GateNotReadyError';
  }
}

// ─── Module-level export ──────────────────────────────────────────────

function selectGate(): GateAuth {
  switch (GATE_MODE) {
    case 'cf-managed-oauth': return new CFManagedOAuthGate();
    case 'iap':              return new IAPGate();
    default: {
      throw new Error(`unknown GATE_MODE: ${GATE_MODE}`);
    }
  }
}

export const gate: GateAuth = selectGate();

// ─── Helpers ──────────────────────────────────────────────────────────

function extractEmail(jwt: string | undefined): string | undefined {
  if (!jwt) return undefined;
  const parts = jwt.split('.');
  if (parts.length !== 3) return undefined;
  try {
    const payload = JSON.parse(
      Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8'),
    );
    return typeof payload.email === 'string' ? payload.email : undefined;
  } catch {
    return undefined;
  }
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]!));
}

function successHtml(email: string | undefined): string {
  const who = email ? escapeHtml(email) : 'your account';
  return (
    '<!doctype html><html><head><meta charset="utf-8"><title>Vikunja MCP — signed in</title>' +
    '<meta name="referrer" content="no-referrer">' +
    '</head>' +
    '<body style="font-family: system-ui, -apple-system, sans-serif; padding: 2rem; text-align: center;">' +
    '<h1>✓ Signed in as ' + who + '</h1>' +
    '<p style="font-size: 1.1rem;">You can close this tab and return to Claude.</p>' +
    '<p style="color: #666; font-size: 0.95rem;">Ask your question again — the full tool set will load automatically.</p>' +
    '<script>setTimeout(function () { try { window.close(); } catch (e) {} }, 400);</script>' +
    '</body></html>'
  );
}

function errorHtml(message: string): string {
  return (
    '<!doctype html><html><head><meta charset="utf-8"><title>Vikunja MCP — sign-in failed</title>' +
    '<meta name="referrer" content="no-referrer">' +
    '</head>' +
    '<body style="font-family: system-ui, -apple-system, sans-serif; padding: 2rem;">' +
    '<h1>Sign-in failed</h1>' +
    '<p>' + message + '</p>' +
    '<p style="color: #666;">Close this tab and ask Claude to restart setup.</p>' +
    '</body></html>'
  );
}
