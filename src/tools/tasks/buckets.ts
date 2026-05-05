/**
 * Kanban bucket move helper.
 *
 * Vikunja v2 stores task-to-bucket relationships per-view, so the legacy
 * `bucket_id` field on the task object is non-writable through the standard
 * task PATCH endpoint (it's silently dropped). The right call is:
 *
 *     POST /projects/{projectId}/views/{viewId}/buckets/{bucketId}/tasks
 *     body: { "task_id": <task id> }
 *
 * If the caller doesn't pass `viewId`, we auto-discover the project's first
 * kanban-mode view via `GET /projects/{projectId}/views`. node-vikunja
 * (v0.4.0) doesn't expose either endpoint, so we use direct fetch with the
 * URL + token from the auth manager session.
 */

import type { AuthManager } from '../../auth/AuthManager';
import { MCPError, ErrorCode } from '../../types';
import { logger } from '../../utils/logger';

interface ProjectView {
  id: number;
  title: string;
  project_id: number;
  view_kind: 'list' | 'gantt' | 'table' | 'kanban' | string;
  position: number;
}

async function fetchJson<T>(url: string, token: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  if (init?.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(url, { ...init, headers });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new MCPError(
      ErrorCode.API_ERROR,
      `Vikunja API ${init?.method ?? 'GET'} ${url} returned ${res.status}: ${text.slice(0, 200)}`,
    );
  }
  return (await res.json()) as T;
}

/**
 * Resolve the kanban view ID for a project. Returns the first view with
 * view_kind='kanban'. Throws if the project has none.
 */
export async function findKanbanViewId(
  authManager: AuthManager,
  projectId: number,
): Promise<number> {
  const { apiUrl, apiToken } = authManager.getSession();
  const views = await fetchJson<ProjectView[]>(
    `${apiUrl}/projects/${projectId}/views`,
    apiToken,
  );
  const kanban = views.find((v) => v.view_kind === 'kanban');
  if (!kanban) {
    throw new MCPError(
      ErrorCode.VALIDATION_ERROR,
      `Project ${projectId} has no kanban view; cannot resolve bucketId without an explicit viewId.`,
    );
  }
  return kanban.id;
}

/**
 * Move a task into a bucket on the specified view. If viewId is omitted,
 * auto-resolves to the project's first kanban view.
 */
export async function moveTaskToBucket(
  authManager: AuthManager,
  taskId: number,
  projectId: number,
  bucketId: number,
  viewId?: number,
): Promise<void> {
  const { apiUrl, apiToken } = authManager.getSession();
  const resolvedViewId = viewId ?? (await findKanbanViewId(authManager, projectId));
  const url = `${apiUrl}/projects/${projectId}/views/${resolvedViewId}/buckets/${bucketId}/tasks`;
  await fetchJson<unknown>(url, apiToken, {
    method: 'POST',
    body: JSON.stringify({ task_id: taskId }),
  });
  logger.info(
    `Moved task ${taskId} to bucket ${bucketId} on project ${projectId} view ${resolvedViewId}`,
  );
}
