#!/usr/bin/env node

/**
 * Vikunja MCP Server — Aircall fleet fork.
 *
 * Forked from democratize-technology/vikunja-mcp. Two changes vs upstream:
 *   1. HTTP transport (Streamable HTTP on 127.0.0.1:<port>) instead of stdio.
 *      Mirrors the looker/gdrive/semrush/storyblok pattern in the fleet —
 *      Caddy reverse-proxies the path-mounted /vikunja/* to this port.
 *   2. API token resolved from GCP Secret Manager via ADC (see ./secrets.ts).
 *      VIKUNJA_API_TOKEN_SECRET_ID names the secret; the value is fetched at
 *      startup so it never lands in env-var listings or systemd unit files.
 */

import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import dotenv from 'dotenv';

import { AuthManager } from './auth/AuthManager';
import { registerTools } from './tools';
import { logger } from './utils/logger';
import { createSecureConnectionMessage, createSecureLogConfig } from './utils/security';
import { createVikunjaClientFactory, setGlobalClientFactory, type VikunjaClientFactory } from './client';
import { resolveApiToken } from './secrets';

dotenv.config({ quiet: true });

const authManager = new AuthManager();

let clientFactory: VikunjaClientFactory | null = null;

async function initializeFactory(): Promise<void> {
  try {
    clientFactory = await createVikunjaClientFactory(authManager);
    if (clientFactory) {
      await setGlobalClientFactory(clientFactory);
    }
  } catch (error) {
    logger.warn('Failed to initialize client factory during startup:', error);
  }
}

// Module-load init: bring up the client factory, then resolve the Vikunja
// API token from Secret Manager (or env fallback) and connect authManager.
// Tool registration happens per request inside buildServer() — keeps the
// auth/client singletons but lets each MCP session own its server instance.
export const factoryInitializationPromise = (async () => {
  await initializeFactory();

  if (process.env.VIKUNJA_URL) {
    const token = await resolveApiToken();
    if (token) {
      const message = createSecureConnectionMessage(process.env.VIKUNJA_URL, token);
      logger.info(`Auto-authenticating: ${message}`);
      authManager.connect(process.env.VIKUNJA_URL, token);
      logger.info(`Using detected auth type: ${authManager.getAuthType()}`);
    }
  }
})();

function buildServer(): McpServer {
  const server = new McpServer({
    name: 'vikunja-mcp',
    version: '0.2.2-aircall',
  });
  if (clientFactory) {
    registerTools(server, authManager, clientFactory);
  } else {
    registerTools(server, authManager, undefined);
  }
  return server;
}

function parsePort(): number {
  const arg = process.argv.find((a) => a.startsWith('--port='));
  if (arg) return Number(arg.slice('--port='.length));
  if (process.env.PORT) return Number(process.env.PORT);
  return 8085;
}

async function main(): Promise<void> {
  await factoryInitializationPromise;

  const app = express();
  app.use(express.json());

  app.get('/health', (_req, res) => {
    res.status(200).send('ok');
  });

  app.post('/mcp', async (req, res) => {
    // Stateless: a fresh server + transport per request. Tools have no
    // per-session state we care about, and this avoids any cross-request
    // contamination. Same shape as mcp-looker/src/index.ts in the fleet.
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      transport.close().catch(() => {});
      server.close().catch(() => {});
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  const port = parsePort();
  app.listen(port, '127.0.0.1', () => {
    logger.info(`Vikunja MCP server listening on http://127.0.0.1:${port}`);
    const config = createSecureLogConfig({
      mode: process.env.MCP_MODE,
      debug: process.env.DEBUG,
      hasAuth:
        !!process.env.VIKUNJA_URL &&
        (!!process.env.VIKUNJA_API_TOKEN || !!process.env.VIKUNJA_API_TOKEN_SECRET_ID),
      url: process.env.VIKUNJA_URL,
      token: 'redacted',
    });
    logger.debug('Configuration loaded', config);
  });
}

if (process.env.NODE_ENV !== 'test' && !process.env.JEST_WORKER_ID) {
  main().catch((error) => {
    logger.error('Failed to start server:', error);
    process.exit(1);
  });
}

// Essential exports preserved from upstream — used by external code/tests.
export { MCPError, ErrorCode } from './types/errors';
export type { TaskResponseData, FilterExpression, Task } from './types';
export type { ParseResult } from './types/filters';
export type { AorpBuilderConfig, AorpFactoryResult } from './types';

export { logger } from './utils/logger';
export { isAuthenticationError } from './utils/auth-error-handler';
export { withRetry, RETRY_CONFIG } from './utils/retry';
export { transformApiError, handleFetchError, handleStatusCodeError } from './utils/error-handler';
export { parseFilterString } from './utils/filters';
export { validateTaskCountLimit } from './utils/memory';
export { createStandardResponse, createAorpErrorResponse as createErrorResponse } from './utils/response-factory';

export type { SimpleResponse } from './utils/simple-response';

export { getClientFromContext, clearGlobalClientFactory } from './client';
