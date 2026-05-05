// Chain smoke test: bridge → local server, full request lifecycle.
//
// Pre-writes an encrypted gate.json so the bridge skips placeholder mode,
// starts the Vikunja server (stubbed Secret Manager + stubbed Vikunja API),
// spawns the bridge with CLOUD_RUN_URL pointed at localhost, and exercises:
//
//   1. tools/list → 7 Vikunja tools forwarded from the server
//      (proves upstream connect + JWT header pass-through)
//   2. tools/call looker_me → stubbed user payload returned
//      (proves bridge → server → Vikunja /login → Vikunja /user → response chain)
//
// Run with:  bun run scripts/smoke-test-chain.ts
// Exits 0 on full pass, 1 on any failure.
//
// What this does NOT validate (because CF Access isn't in front of the local
// server): JWT signature verification, IdP audience claims, deny-rule
// enforcement. Those are CF's responsibility and live in stage 6, not 7.

import { spawn } from "node:child_process";
import { rm, mkdir, writeFile } from "node:fs/promises";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { encrypt } from "../src/credentials.ts";
import { GATE_PATH, CONFIG_DIR } from "../src/paths.ts";

const BINARY = new URL("../dist/vikunja-bridge", import.meta.url).pathname;
const TEST_PORT = 18080;
const TEST_BASE_URL = "https://looker.smoke.test";

let failed = false;
const fail = (msg: string) => {
  console.error(`[chain] FAIL: ${msg}`);
  failed = true;
};
const ok = (msg: string) => console.error(`[chain] PASS: ${msg}`);

// ─── Pre-write gate.json with a fake JWT ─────────────────────────────

await rm(CONFIG_DIR, { recursive: true, force: true });
await mkdir(CONFIG_DIR, { recursive: true, mode: 0o700 });

const fakeGateCreds = {
  jwt: "smoke.test.jwt",
  refreshToken: "smoke.test.refresh",
  jwtExpiresAt: Date.now() + 24 * 60 * 60 * 1000,
  email: "smoke@aircall.io",
  savedAt: new Date().toISOString(),
  mode: "cf-sso" as const,
};
const envelope = encrypt(JSON.stringify(fakeGateCreds));
await writeFile(GATE_PATH, envelope, { mode: 0o600 });
ok("wrote encrypted fake gate.json");

// ─── Stub fetch for Vikunja API calls ────────────────────────────────

const STUB_USER = {
  id: 42,
  email: "chain@aircall.io",
  display_name: "Chain Test",
  first_name: "Chain",
  last_name: "Test",
  is_disabled: false,
  role_ids: [1],
  verified_looker_employee: false,
};
const STUB_ROLES = [{ id: 1, name: "Marketing Analyst" }];

const originalFetch = globalThis.fetch;
globalThis.fetch = async (url: any, init: any) => {
  const u = typeof url === "string" ? url : url.toString();
  if (u.startsWith(TEST_BASE_URL)) {
    if (u.endsWith("/api/4.0/login")) {
      return new Response(
        JSON.stringify({ access_token: "chain.token", expires_in: 3600, token_type: "Bearer" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (u.endsWith("/api/4.0/user")) {
      return new Response(JSON.stringify(STUB_USER), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (u.includes(`/users/${STUB_USER.id}/roles`)) {
      return new Response(JSON.stringify(STUB_ROLES), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ message: "stub miss" }), { status: 404 });
  }
  return originalFetch(url, init);
};

// ─── Spin up an inline Vikunja server with stubs ─────────────────────

const secretsModule: any = await import("../../../src/secrets.ts");
secretsModule._setSecretsForTests({
  base_url: TEST_BASE_URL,
  client_id: "chain-client-id",
  client_secret: "chain-client-secret",
});

const { VikunjaClient } = await import("../../../src/looker/client.ts");
const { loadConfig } = await import("../../../src/config.ts");
const meTool = await import("../../../src/looker/tools/me.ts");
const listDashTool = await import("../../../src/looker/tools/list_dashboards.ts");
const getDashTool = await import("../../../src/looker/tools/get_dashboard.ts");
const listLooksTool = await import("../../../src/looker/tools/list_looks.ts");
const runLookTool = await import("../../../src/looker/tools/run_look.ts");
const runIqTool = await import("../../../src/looker/tools/run_inline_query.ts");
const runDashTool = await import("../../../src/looker/tools/run_dashboard.ts");

type ToolResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };
const textResult = (text: string): ToolResult => ({ content: [{ type: "text", text }] });
const errorResult = (m: string): ToolResult => ({ content: [{ type: "text", text: m }], isError: true });

function buildMcp() {
  const s = new McpServer(
    { name: "aircall-vikunja", version: "chain-test" },
    { capabilities: { tools: { listChanged: true } } },
  );
  const wrap = <T>(_tool: string, fn: (c: any) => Promise<T>): Promise<ToolResult> => {
    const c = new VikunjaClient(loadConfig());
    return fn(c)
      .then((out) => textResult(typeof out === "string" ? out : JSON.stringify(out)))
      .catch((err) => errorResult(err instanceof Error ? err.message : String(err)));
  };
  s.registerTool(
    "looker_me",
    { description: meTool.meDescription, inputSchema: meTool.meInputSchema },
    () => wrap("looker_me", (c) => meTool.runMe(c)),
  );
  s.registerTool(
    "looker_list_dashboards",
    { description: listDashTool.listDashboardsDescription, inputSchema: listDashTool.listDashboardsInputSchema },
    (args: any) => wrap("looker_list_dashboards", (c) => listDashTool.runListDashboards(c, args)),
  );
  s.registerTool(
    "looker_get_dashboard",
    { description: getDashTool.getDashboardDescription, inputSchema: getDashTool.getDashboardInputSchema },
    (args: any) => wrap("looker_get_dashboard", (c) => getDashTool.runGetDashboard(c, args)),
  );
  s.registerTool(
    "looker_list_looks",
    { description: listLooksTool.listLooksDescription, inputSchema: listLooksTool.listLooksInputSchema },
    (args: any) => wrap("looker_list_looks", (c) => listLooksTool.runListLooks(c, args)),
  );
  s.registerTool(
    "looker_run_look",
    { description: runLookTool.runLookDescription, inputSchema: runLookTool.runLookInputSchema },
    (args: any) => wrap("looker_run_look", (c) => runLookTool.runRunLook(c, args)),
  );
  s.registerTool(
    "looker_run_inline_query",
    { description: runIqTool.runInlineQueryDescription, inputSchema: runIqTool.runInlineQueryInputSchema },
    (args: any) => wrap("looker_run_inline_query", (c) => runIqTool.runRunInlineQuery(c, args)),
  );
  s.registerTool(
    "looker_run_dashboard",
    { description: runDashTool.runDashboardDescription, inputSchema: runDashTool.runDashboardInputSchema },
    (args: any) => wrap("looker_run_dashboard", (c) => runDashTool.runRunDashboard(c, args)),
  );
  return s;
}

const app = express();
app.use(express.json());

let receivedJwtHeader: string | null = null;
app.use((req, _res, next) => {
  const v = req.headers["cf-access-jwt-assertion"];
  if (typeof v === "string") receivedJwtHeader = v;
  next();
});

app.get("/health", (_req, res) => res.status(200).send("ok"));
app.post("/mcp", async (req, res) => {
  const s = buildMcp();
  const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    t.close().catch(() => {});
    s.close().catch(() => {});
  });
  await s.connect(t);
  await t.handleRequest(req, res, req.body);
});

const httpServer = await new Promise<any>((resolve) => {
  const x = app.listen(TEST_PORT, "127.0.0.1", () => resolve(x));
});
ok(`local Vikunja server listening on 127.0.0.1:${TEST_PORT}`);

// ─── Spawn bridge pointed at the local server ────────────────────────

const proc = spawn(BINARY, [], {
  env: {
    ...process.env,
    CF_ACCESS_TEAM_DOMAIN: "dummy",
    CF_ACCESS_APP_AUD: "dummy",
    CLOUD_RUN_URL: `http://127.0.0.1:${TEST_PORT}`,
  },
  stdio: ["pipe", "pipe", "pipe"],
});

let stdoutBuf = "";
const pendingResponses = new Map<number, (msg: any) => void>();

proc.stdout!.setEncoding("utf-8");
proc.stdout!.on("data", (chunk: string) => {
  stdoutBuf += chunk;
  let nl: number;
  while ((nl = stdoutBuf.indexOf("\n")) >= 0) {
    const line = stdoutBuf.slice(0, nl).trim();
    stdoutBuf = stdoutBuf.slice(nl + 1);
    if (!line) continue;
    try {
      const msg = JSON.parse(line);
      if (typeof msg.id === "number" && pendingResponses.has(msg.id)) {
        pendingResponses.get(msg.id)!(msg);
        pendingResponses.delete(msg.id);
      }
    } catch {}
  }
});
proc.stderr!.setEncoding("utf-8");
proc.stderr!.on("data", (chunk: string) => process.stderr.write(`[bridge] ${chunk}`));

function send(id: number, method: string, params: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingResponses.delete(id);
      reject(new Error(`timeout waiting for response to ${method} (id=${id})`));
    }, 8000);
    pendingResponses.set(id, (msg) => {
      clearTimeout(timer);
      resolve(msg);
    });
    proc.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

try {
  await new Promise((r) => setTimeout(r, 300));
  if (proc.exitCode !== null) {
    throw new Error(`bridge crashed before any frames could be sent (code=${proc.exitCode})`);
  }
  ok("bridge process started and is running");

  // initialize
  const initRes = await send(1, "initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "chain", version: "0" },
  });
  if (initRes.result?.serverInfo?.name === "vikunja-mcp") {
    ok(`initialize → serverInfo.name=${initRes.result.serverInfo.name}`);
  } else {
    fail(`initialize returned ${JSON.stringify(initRes).slice(0, 200)}`);
  }
  proc.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

  // tools/list — should now be the FULL set forwarded from the server (not placeholder)
  const listRes = await send(2, "tools/list", {});
  const tools = (listRes.result?.tools ?? []).map((t: any) => t.name).sort();
  const expected = [
    "looker_get_dashboard",
    "looker_list_dashboards",
    "looker_list_looks",
    "looker_me",
    "looker_run_dashboard",
    "looker_run_inline_query",
    "looker_run_look",
  ];
  if (JSON.stringify(tools) === JSON.stringify(expected)) {
    ok(`tools/list (chain) → ${tools.length} tools forwarded from server`);
  } else {
    fail(`tools/list returned ${JSON.stringify(tools)}`);
  }

  // Verify the gate JWT header propagated to the server
  if (receivedJwtHeader === "smoke.test.jwt") {
    ok(`server received cf-access-jwt-assertion=${receivedJwtHeader}`);
  } else {
    fail(`server received cf-access-jwt-assertion=${receivedJwtHeader} (expected smoke.test.jwt)`);
  }

  // tools/call looker_me — full chain through Vikunja /login + /user
  const callRes = await send(3, "tools/call", {
    name: "looker_me",
    arguments: {},
  });
  const text = callRes.result?.content?.[0]?.text ?? "";
  if (
    text.includes("Chain Test") &&
    text.includes("chain@aircall.io") &&
    text.includes("Marketing Analyst")
  ) {
    ok("tools/call looker_me (chain) → user payload contains stubbed name + email + role");
  } else {
    fail(`tools/call looker_me returned: ${text.slice(0, 200)}`);
  }
} finally {
  proc.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 100));
  if (proc.exitCode === null) proc.kill("SIGKILL");
  httpServer.close();
}

if (failed) {
  console.error("[chain] one or more checks failed");
  process.exit(1);
}
console.error("[chain] all checks passed");
process.exit(0);
