// Configuration for the Vikunja bridge.
//
// Vikunja is a shared-key MCP from the bridge's perspective — the per-user
// auth happens at the edge (Cloudflare Access Managed OAuth). The Vikunja
// API token lives server-side in GCP Secret Manager and never reaches any
// pilot machine. The only auth the bridge performs is against the edge gate.

// Server URL is overridable via env at runtime so smoke tests can point the
// binary at localhost without rebuilding. URL is not a credential — the
// override does not relax the no-baked-creds rule.
export const CLOUD_RUN_URL =
  process.env.CLOUD_RUN_URL ?? 'https://mcp.trentmorris.dev/vikunja';

// ─── Gate auth configuration ──────────────────────────────────────────
//
// Default mode: 'cf-managed-oauth' (Cloudflare Access self-hosted app
// with Managed OAuth toggled on — turns the Access app into an OAuth 2.0
// authorization server with discovery at <app-domain>/.well-known/
// oauth-authorization-server, RFC 7591 dynamic registration, and PKCE
// for public clients).
// Alternative: 'iap' (GCP IAP — stub today; real impl when migrating).
// Pluggability lives in `gate.ts`; selecting between modes is a build-
// time concern via the GATE_MODE env var.

export const GATE_MODE: 'cf-managed-oauth' | 'iap' =
  (process.env.GATE_MODE as 'cf-managed-oauth' | 'iap') ?? 'cf-managed-oauth';

// CF Access team domain — the prefix of <x>.cloudflareaccess.com. Same
// across the fleet (one team domain). Public value (visible in DNS).
export const CF_ACCESS_TEAM_DOMAIN = process.env.CF_ACCESS_TEAM_DOMAIN ?? 'trentmorris';

// CF Managed OAuth client_id — registered once via the team's
// /cdn-cgi/access/oauth/registration endpoint. Same client_id is shared
// by every fleet bridge (public client + PKCE; no secret to leak). The
// value is public (matches fleet STATE.yaml fleet_cf_oauth_client_id).
export const CF_OAUTH_CLIENT_ID =
  process.env.CF_OAUTH_CLIENT_ID ?? '554adf25-cabe-47ff-873e-607aa6014f5c';

if (GATE_MODE === 'cf-managed-oauth' && (!CF_ACCESS_TEAM_DOMAIN || !CF_OAUTH_CLIENT_ID)) {
  throw new Error(
    'CF_ACCESS_TEAM_DOMAIN and CF_OAUTH_CLIENT_ID must be set at build time when GATE_MODE=cf-managed-oauth',
  );
}

// CF Managed OAuth access tokens are short-lived (default 15 min, configurable
// up to 24h via the Access app's Advanced settings). The cache TTL below is set
// to refresh proactively before expiry. Tighter than the legacy SaaS-OIDC 24h
// JWT — so we use the access_token's own expires_in field at runtime rather
// than capping at this constant. Kept as a hard upper bound regardless.
export const GATE_TOKEN_CACHE_MS = 23 * 60 * 60 * 1000;
