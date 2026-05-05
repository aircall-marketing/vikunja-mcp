// Vikunja API token resolution for the Aircall fleet fork.
//
// Two resolution paths, in priority order:
//   1. VIKUNJA_API_TOKEN_SECRET_ID + GOOGLE_CLOUD_PROJECT — fetch from
//      GCP Secret Manager via Application Default Credentials. This is
//      the production path on the fleet VM (compute SA has secretAccessor).
//   2. VIKUNJA_API_TOKEN — direct env var. Legacy / dev path; useful for
//      `npm run dev` against a local Vikunja instance.
//
// Returns null if neither resolves; the caller logs a warning and the auth
// manager stays in unconfigured state (every tool call will return a clear
// error rather than a partial result).

import { SecretManagerServiceClient } from '@google-cloud/secret-manager';

import { logger } from './utils/logger';

let cachedClient: SecretManagerServiceClient | null = null;

function getClient(): SecretManagerServiceClient {
  if (!cachedClient) {
    cachedClient = new SecretManagerServiceClient();
  }
  return cachedClient;
}

export async function resolveApiToken(): Promise<string | null> {
  const secretId = process.env.VIKUNJA_API_TOKEN_SECRET_ID;
  if (secretId) {
    const project = process.env.GOOGLE_CLOUD_PROJECT;
    if (!project) {
      logger.error(
        'VIKUNJA_API_TOKEN_SECRET_ID is set but GOOGLE_CLOUD_PROJECT is not — cannot resolve secret',
      );
      return null;
    }
    try {
      const [version] = await getClient().accessSecretVersion({
        name: `projects/${project}/secrets/${secretId}/versions/latest`,
      });
      const payload = version.payload?.data;
      if (!payload) {
        logger.error(`Secret ${secretId} returned empty payload`);
        return null;
      }
      const token = Buffer.from(payload).toString('utf-8').trim();
      logger.info(`Resolved Vikunja API token from Secret Manager (${secretId})`);
      return token;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to fetch ${secretId} from Secret Manager: ${message}`);
      return null;
    }
  }

  const direct = process.env.VIKUNJA_API_TOKEN;
  if (direct) {
    logger.info('Using VIKUNJA_API_TOKEN directly from env (no Secret Manager)');
    return direct;
  }

  return null;
}
