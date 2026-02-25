# Phase 11: Multi-Tenant and RBAC Detailed Implementation Report

## Objective
Enforce strict tenant isolation and route-level authorization with clear role/permission governance.

## Current Baseline
- Org IDs and auth exist.

## Critical Gaps
- Permission system is not fully formalized.
- Role management and invites are incomplete.
- Inconsistent route-level authorization checks.

## Required Fixes
- Define role taxonomy (`owner`, `admin`, `analyst`, `viewer`).
- Define permission matrix per resource/action.
- Add org invite and membership lifecycle.
- Add mandatory scoped query helpers.

## Data Model
- `roles`
- `permissions`
- `role_permissions`
- `user_roles`
- `org_invites`

## API Plan
- `POST /api/orgs/:orgId/invites`
- `GET /api/orgs/:orgId/invites`
- `POST /api/invites/:token/accept`
- `PATCH /api/orgs/:orgId/users/:userId/roles`
- `GET /api/orgs/:orgId/permissions`

## UI Plan
- Organization settings page for members/invites/roles.
- Action-level gating and disabled states.

## Testing
- Permission resolver tests.
- Cross-tenant isolation tests.
- Invite flow integration tests.

## Definition of Done
- Every protected endpoint enforces permissions and tenant scoping.
