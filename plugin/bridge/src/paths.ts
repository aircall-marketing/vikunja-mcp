import { homedir } from 'node:os';
import { join } from 'node:path';

function configDir(): string {
  const xdg = process.env.XDG_CONFIG_HOME;
  const base = xdg && xdg.trim().length > 0 ? xdg : join(homedir(), '.config');
  return join(base, 'aircall-vikunja-mcp');
}

export const CONFIG_DIR = configDir();
export const GATE_PATH = join(CONFIG_DIR, 'gate.json');
export const LOG_PATH = join(CONFIG_DIR, 'bridge.log');
