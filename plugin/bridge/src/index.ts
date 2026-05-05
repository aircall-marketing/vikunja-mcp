// Stdio MCP bridge for Vikunja. Claude Desktop spawns this binary; it reads
// JSON-RPC frames from stdin, forwards them to the hosted MCP server with a
// CF Access JWT in the cf-access-jwt-assertion header, and writes upstream
// responses back to stdout. Vikunja is shared-key — there is no per-user
// vendor OAuth, so the only credential the bridge holds is the gate JWT,
// persisted at ~/.config/aircall-vikunja-mcp/gate.json (AES-256-GCM
// envelope, key bound to machine UUID + UID).

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { CLOUD_RUN_URL } from './config.ts';
import { gate, GateNotReadyError, type PendingGateAuth } from './gate.ts';
import { log } from './log.ts';

// GOTCHA: see GOTCHAS.md §"Placeholder mode flips on credential presence".
// Bridge runs in one of two modes, togglable at runtime:
//   - Full mode: forward all MCP traffic to the hosted server with the gate JWT.
//   - Placeholder mode: expose only the begin-setup tool, which runs the
//     CF Access SSO flow, then exits the process so Claude Desktop respawns
//     into full mode. Entered on cold start when the gate isn't ready, and
//     re-entered mid-session on GateNotReadyError.
let placeholderMode = false;
let pendingGate: PendingGateAuth | null = null;

const BEGIN_SETUP_TOOL = {
  name: 'vikunja_begin_setup',
  description:
    'Vikunja MCP requires a one-time sign-in before any tools are available. Call this tool whenever the user asks for Vikunja functionality and no Vikunja tools are exposed yet. Returns a clickable auth URL for the user to sign in; after they sign in, the full tool set will load automatically on their next query. Call this tool without asking the user for confirmation — they just need to click the URL you show them.',
  inputSchema: { type: 'object' as const, properties: {} },
};

async function enterPlaceholderMode(downstream: Server | null): Promise<void> {
  if (placeholderMode) return;
  placeholderMode = true;
  gate.invalidate();
  await log('warn', 'gate not ready — entering placeholder mode', {});
  await (downstream as unknown as { sendToolListChanged?: () => Promise<void> })
    ?.sendToolListChanged?.()
    .catch(() => {});
}

async function handleBeginSetup(toolName: string): Promise<{
  content: Array<{ type: 'text'; text: string }>;
  isError: boolean;
}> {
  if (toolName !== 'vikunja_begin_setup') {
    return {
      content: [{
        type: 'text' as const,
        text: 'Your Vikunja sign-in expired. Call the vikunja_begin_setup tool to re-authenticate.',
      }],
      isError: true,
    };
  }

  if (pendingGate) {
    pendingGate.cancel();
    pendingGate = null;
  }
  const pending = await gate.bootstrap();
  pendingGate = pending;
  await log('info', 'gate setup listener started', {});
  pending.onComplete.then(
    async () => {
      await log('info', 'gate setup completed; scheduling exit for respawn', {});
      setTimeout(() => process.exit(0), 750).unref();
    },
    async (err) => {
      await log('error', 'gate setup failed', { error: err.message });
      pendingGate = null;
    },
  );
  return formatSetupMessage(pending.authUrl);
}

function formatSetupMessage(authUrl: string): {
  content: Array<{ type: 'text'; text: string }>;
  isError: boolean;
} {
  const userMessage =
    `To use this custom connector, please [sign in to access your team's tools](${authUrl}). ` +
    `You'll only have to do this once.\n\n` +
    `After signing in, send your request in this chat again.`;
  const instructions =
    `[INSTRUCTION FOR THE ASSISTANT: show the following message to the user exactly as written, ` +
    `with the link rendered as a hyperlink. Do not paraphrase, do not expose the raw URL, ` +
    `do not mention OAuth, tokens, PKCE, or loopback ports.]\n\n` +
    `---\n\n` +
    userMessage;
  return {
    content: [{ type: 'text' as const, text: instructions }],
    isError: false,
  };
}

async function main(): Promise<void> {
  const gateReady = await gate.isReady();
  let upstream: Client | null = null;

  if (gateReady) {
    await log('info', 'bridge starting', { cloudRunUrl: CLOUD_RUN_URL });

    upstream = new Client(
      { name: 'vikunja-bridge', version: '0.1.0' },
      { capabilities: {} },
    );

    // GOTCHA: see GOTCHAS.md §"Custom headers survive Cloudflare". The fetch
    // hook applies the gate JWT on every outbound request. On 401, invalidate
    // and retry once. GateNotReadyError propagates up to the downstream
    // handler's catch, which flips placeholder mode.
    const upstreamTransport = new StreamableHTTPClientTransport(new URL(`${CLOUD_RUN_URL}/mcp`), {
      requestInit: {},
      fetch: async (input, init) => {
        const headers = new Headers(init?.headers);
        await gate.applyHeaders(headers);
        const res = await fetch(input, { ...init, headers });
        if (res.status !== 401) return res;
        gate.invalidate();
        const retryHeaders = new Headers(init?.headers);
        await gate.applyHeaders(retryHeaders);
        return await fetch(input, { ...init, headers: retryHeaders });
      },
    });

    try {
      await upstream.connect(upstreamTransport);
      await log('info', 'upstream connected', {});
    } catch (err) {
      // Distinguish auth failures (CF served the login HTML page, meaning
      // the gate creds aren't valid at the edge) from upstream server
      // failures (server returned a JSON-RPC error, network error, etc).
      // Auth failures: clear gate creds so the next launch starts fresh.
      // Upstream failures: keep the gate creds — the user's sign-in is
      // still valid; only the server is having trouble. Otherwise a
      // transient hiccup wipes the pilot's auth and forces a re-sign.
      const message = (err as Error).message;
      const looksLikeAuthFailure = message.includes('text/html');
      await log('warn', 'upstream connect failed; falling into placeholder mode', {
        error: message,
        clearedGate: looksLikeAuthFailure,
      });
      if (looksLikeAuthFailure) {
        await gate.clear().catch(() => {});
      }
      upstream = null;
      placeholderMode = true;
    }
  } else {
    placeholderMode = true;
    await log('info', 'starting in placeholder mode', { gateReady });
  }

  const downstream = new Server(
    { name: 'vikunja-mcp', version: '0.1.0' },
    { capabilities: { tools: { listChanged: true }, resources: {} } },
  );

  downstream.setRequestHandler(ListToolsRequestSchema, async () => {
    if (placeholderMode || !upstream) {
      return { tools: [BEGIN_SETUP_TOOL] };
    }
    const upstreamResult = await upstream.listTools();
    return { tools: upstreamResult.tools };
  });

  downstream.setRequestHandler(CallToolRequestSchema, async (req) => {
    if (placeholderMode || !upstream) {
      return handleBeginSetup(req.params.name);
    }
    try {
      // GOTCHA: see GOTCHAS.md §"Long operations must return handles".
      // 60-minute call timeout is the upper bound managed HTTP services
      // typically allow.
      return await upstream.callTool(req.params, undefined, { timeout: 3_600_000 });
    } catch (err) {
      if (err instanceof GateNotReadyError) {
        await enterPlaceholderMode(downstream);
        return {
          content: [{
            type: 'text' as const,
            text: 'Your sign-in expired. Call the vikunja_begin_setup tool to re-authenticate.',
          }],
          isError: true,
        };
      }
      throw err;
    }
  });

  downstream.setRequestHandler(ListResourcesRequestSchema, async (req) => {
    if (placeholderMode || !upstream) return { resources: [] };
    return upstream.listResources(req.params);
  });
  downstream.setRequestHandler(ReadResourceRequestSchema, async (req) => {
    if (placeholderMode || !upstream) {
      throw new Error('Vikunja sign-in expired; no resources available until re-auth');
    }
    return upstream.readResource(req.params);
  });

  const downstreamTransport = new StdioServerTransport();
  await downstream.connect(downstreamTransport);
  await log('info', placeholderMode ? 'placeholder server ready on stdio' : 'bridge ready on stdio', {});

  const shutdown = async (signal: string) => {
    await log('info', 'shutting down', { signal });
    if (pendingGate) {
      pendingGate.cancel();
      pendingGate = null;
    }
    await upstream?.close().catch(() => {});
    await downstream.close().catch(() => {});
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

main().catch(async (err) => {
  await log('error', 'fatal error in main', { error: (err as Error).message, stack: (err as Error).stack });
  process.stderr.write(`vikunja-bridge fatal: ${(err as Error).message}\n`);
  process.exit(1);
});
