# XAuth SDK/API

The lightweight consumer SDK is in `sdk/src/index.ts`. It contains no server internals, role logic, or service-role key. Both independent test applications should create one `XAuthClient` and use it to call the XAuth API; they must not copy authentication code.

```ts
import { XAuthClient } from '@archscale/xauth-sdk';

const auth = new XAuthClient({ baseURL: import.meta.env.VITE_API_URL || '' });
auth.setAccessToken(accessToken); // memory only
auth.setContext(contextId);
const result = await auth.request<{ tasks: unknown[] }>('/api/tasks');
if (!result.ok) throw new Error(result.message);
```

The foundation API performs authentication and RLS policy checks. Consumer applications must not trust local role labels to authorize actions.

## Current API groups

- Session: `POST /api/session/sign-in`, `POST /api/session/mfa/verify`, `POST /api/session/refresh`, `POST /api/session/recovery`, `POST /api/session/reset-password`, `GET /api/session/memberships`, `GET /api/session/workspaces`, `POST /api/session/context`, `POST /api/session/logout`.
- Organization: `/api/org/members`, `/api/org/invitations`, `/api/org/settings/mfa`.
- Tasks: `GET/POST /api/tasks`, `PATCH /api/tasks/:id`, `POST /api/tasks/:id/approve`.
- Attendance: `GET /api/attendance`, `PATCH /api/attendance/:id`, `POST /api/attendance/:id/comment`.

Task and attendance authorization uses the active XAuth context and database RLS. App records are tenant scoped. `created_by_membership_id` is bound by the database, reassignments append audit history, and attendance comments are insert-only. The SDK keeps tokens in memory and attempts one refresh after a 401; failed refresh dispatches `xauth:unauthorized` so the client can clear local session state. Configure each tenant's `tasks` and `attendance` entitlements before use.

This SDK is currently a source package consumed by the bundled frontend. There are no independent Tasks/Attendance repositories in this checkout, no published npm artifact, and no SDK compatibility/versioning process yet. The requested independent consumer apps and module uninstall/reinstall tests remain pending.
