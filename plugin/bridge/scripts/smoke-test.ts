// Bridge-side smoke test for the Vikunja MCP bridge.
//
// Spawns the compiled binary with no gate creds on disk, pipes MCP frames
// over stdio, and asserts placeholder-mode behavior:
//
//   1. Process starts and stays running.
//   2. initialize handshake responds with serverInfo.name=vikunja-mcp.
//   3. tools/list returns exactly one tool: vikunja_begin_setup.
//   4. The bridge can be cleanly shut down.
//
// Run with:  bun run scripts/smoke-test.ts
// Exits 0 on full pass, 1 on any failure.
//
// Note: the chain test (bridge → server with a populated gate.json) is a
// stage 7 deliverable and not exercised here. Stage 7 will mirror this
// script and add the upstream forwarding assertions.

import { spawn } from "node:child_process";
import { rm, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const BINARY = new URL("../dist/vikunja-bridge", import.meta.url).pathname;
const CONFIG_DIR = join(homedir(), ".config", "aircall-vikunja-mcp");

let failed = false;
const fail = (msg: string) => {
  console.error(`[smoke] FAIL: ${msg}`);
  failed = true;
};
const ok = (msg: string) => console.error(`[smoke] PASS: ${msg}`);

// Wipe any cached gate creds so we start cleanly in placeholder mode.
await rm(CONFIG_DIR, { recursive: true, force: true });
await mkdir(CONFIG_DIR, { recursive: true, mode: 0o700 });

const proc = spawn(BINARY, [], {
  env: {
    ...process.env,
    // Build/runtime env: dummy CF values are fine in placeholder mode —
    // the bridge never reaches the OIDC endpoints unless begin_setup runs.
    CF_ACCESS_TEAM_DOMAIN: "dummy",
    CF_ACCESS_APP_AUD: "dummy",
  },
  stdio: ["pipe", "pipe", "pipe"],
});

// Buffer stdout and parse line-delimited JSON-RPC responses.
let stdoutBuf = "";
const pendingResponses = new Map<number, (msg: any) => void>();

proc.stdout.setEncoding("utf-8");
proc.stdout.on("data", (chunk: string) => {
  stdoutBuf += chunk;
  let nl;
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
    } catch {
      // Ignore non-JSON lines (shouldn't happen — stdout is the protocol channel).
    }
  }
});

proc.stderr.setEncoding("utf-8");
proc.stderr.on("data", (chunk: string) => {
  // Surface bridge stderr for debug visibility.
  process.stderr.write(`[bridge stderr] ${chunk}`);
});

proc.on("exit", (code, signal) => {
  if (code !== 0 && code !== null) {
    console.error(`[smoke] bridge exited with code=${code} signal=${signal}`);
  }
});

function send(id: number, method: string, params: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingResponses.delete(id);
      reject(new Error(`timeout waiting for response to ${method} (id=${id})`));
    }, 5000);
    pendingResponses.set(id, (msg) => {
      clearTimeout(timer);
      resolve(msg);
    });
    proc.stdin.write(
      JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n",
    );
  });
}

try {
  // Give the bridge a moment to wire up stdio.
  await new Promise((r) => setTimeout(r, 200));

  if (proc.exitCode !== null) {
    throw new Error(`bridge crashed before any frames could be sent (code=${proc.exitCode})`);
  }
  ok("bridge process started and is running");

  // 1. initialize
  const initRes = await send(1, "initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "smoke", version: "0" },
  });
  if (initRes.result?.serverInfo?.name === "vikunja-mcp") {
    ok(`initialize → serverInfo.name=${initRes.result.serverInfo.name}`);
  } else {
    fail(`initialize returned ${JSON.stringify(initRes).slice(0, 200)}`);
  }

  // initialized notification (no id, no response)
  proc.stdin.write(
    JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n",
  );

  // 2. tools/list — should return placeholder-mode set (just begin_setup)
  const listRes = await send(2, "tools/list", {});
  const tools = listRes.result?.tools ?? [];
  const names = tools.map((t: any) => t.name);
  if (names.length === 1 && names[0] === "vikunja_begin_setup") {
    ok(`tools/list (placeholder mode) → [${names[0]}]`);
  } else {
    fail(`tools/list returned ${JSON.stringify(names)}, expected [vikunja_begin_setup]`);
  }

  // 3. The placeholder tool's description should be specific (not the generic shape).
  const setupTool = tools[0];
  if (setupTool?.description?.includes("Vikunja MCP requires a one-time sign-in")) {
    ok("begin_setup description starts with Vikunja-specific copy");
  } else {
    fail(`begin_setup description unexpected: ${setupTool?.description?.slice(0, 80)}`);
  }
} finally {
  proc.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 100));
  if (proc.exitCode === null) proc.kill("SIGKILL");
}

if (failed) {
  console.error("[smoke] one or more checks failed");
  process.exit(1);
}
console.error("[smoke] all checks passed");
process.exit(0);
