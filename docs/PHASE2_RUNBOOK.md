# ArchScale Phase 2 End-to-End Runbook

This runbook documents the exact flow to exercise the Phase 2 authentication and authorization pipeline against the local or staging server.

---

### Prerequisites
1. Server running on `127.0.0.1:3000` (or ephemeral port):
   ```bash
   npm run server
   ```
2. Staging test users seeded:
   ```bash
   npx tsx scripts/seed_staging_users.ts --confirm-staging
   ```
3. Current TOTP code helper (for MFA-enabled users):
   ```bash
   npx tsx scripts/totp_code.ts <user-key> --confirm-local
   ```

---

### Step-by-Step API Flow

#### Step 1: Sign-In
- **Endpoint**: `POST /api/session/sign-in`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
    "email": "TEST-owner-...@archscale.test",
    "password": "<PASSWORD>"
  }
  ```
- **Response**: `200 OK`
  ```json
  {
    "accessToken": "<BEARER_TOKEN>",
    "refreshToken": "<REFRESH_TOKEN>",
    "principal": {
      "id": "<USER_UUID>",
      "email": "...",
      "aal": "aal1"
    },
    "mfaRequired": true
  }
  ```

#### Step 2: MFA TOTP Verify (AAL2 Upgrade)
- **Endpoint**: `POST /api/session/mfa/verify`
- **Headers**:
  - `Content-Type: application/json`
  - `Authorization: Bearer <BEARER_TOKEN>`
- **Body**:
  ```json
  {
    "code": "123456"
  }
  ```
- **Response**: `200 OK`
  ```json
  {
    "accessToken": "<NEW_AAL2_BEARER_TOKEN>",
    "refreshToken": "<REFRESH_TOKEN>",
    "aal": "aal2"
  }
  ```

#### Step 3: List Principal Memberships
- **Endpoint**: `GET /api/session/memberships`
- **Headers**:
  - `Authorization: Bearer <NEW_AAL2_BEARER_TOKEN>`
- **Response**: `200 OK`
  ```json
  {
    "memberships": [
      {
        "membership_id": "<MEMBERSHIP_UUID>",
        "organisation_id": "<ORGANISATION_UUID>",
        "organisation_name": "TEST-Studio Architecture",
        "role_key": "business_owner",
        "portal": "subscriber",
        "tenant_type_key": "studio_owner"
      }
    ]
  }
  ```

#### Step 4: List Organisation Workspaces
- **Endpoint**: `GET /api/session/workspaces?organisationId=<ORGANISATION_UUID>`
- **Headers**:
  - `Authorization: Bearer <NEW_AAL2_BEARER_TOKEN>`
- **Response**: `200 OK`
  ```json
  {
    "workspaces": [
      {
        "workspace_id": "<WORKSPACE_UUID>",
        "workspace_name": "Studio Main WS",
        "is_default": false,
        "is_active": true
      }
    ]
  }
  ```

#### Step 5: Issue Access Context
- **Endpoint**: `POST /api/session/context`
- **Headers**:
  - `Content-Type: application/json`
  - `Authorization: Bearer <NEW_AAL2_BEARER_TOKEN>`
- **Body**:
  ```json
  {
    "organisationId": "<ORGANISATION_UUID>",
    "workspaceId": "<WORKSPACE_UUID>"
  }
  ```
- **Response**: `200 OK`
  ```json
  {
    "context": {
      "contextId": "<CONTEXT_UUID>",
      "expiresAt": "2026-10-29T18:00:00.000Z"
    }
  }
  ```

#### Step 6: Call Context-Protected Route (`/api/me`)
- **Endpoint**: `GET /api/me`
- **Headers**:
  - `Authorization: Bearer <NEW_AAL2_BEARER_TOKEN>`
  - `X-ArchScale-Context: <CONTEXT_UUID>`
- **Response**: `200 OK`

#### Step 7: Call Permission-Gated Mutation (`/api/org/invitations`)
- **Endpoint**: `POST /api/org/invitations`
- **Headers**:
  - `Content-Type: application/json`
  - `Authorization: Bearer <NEW_AAL2_BEARER_TOKEN>`
  - `X-ArchScale-Context: <CONTEXT_UUID>`
- **Body**:
  ```json
  {
    "email": "colleague@studio.test",
    "roleKey": "leader"
  }
  ```
- **Response**: `200 OK`

#### Step 8: Renew Context
- **Endpoint**: `POST /api/session/context/renew`
- **Headers**:
  - `Authorization: Bearer <NEW_AAL2_BEARER_TOKEN>`
  - `X-ArchScale-Context: <CONTEXT_UUID>`
- **Response**: `200 OK`

#### Step 9: Logout & Revocation
- **Endpoint**: `POST /api/session/logout`
- **Headers**:
  - `Authorization: Bearer <NEW_AAL2_BEARER_TOKEN>`
  - `X-ArchScale-Context: <CONTEXT_UUID>`
- **Response**: `200 OK`
- Subsequent calls with the same token or context return `401 Unauthorized`.

