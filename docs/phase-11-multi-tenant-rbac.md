# Phase 11: Multi-Tenant and RBAC Detailed Implementation Report

## 1. Executive Summary
Phase 11 is foundational for production SaaS trust. It must enforce strict tenant isolation and role-based authorization at query, route, and UI levels.

## 2. Objectives
- Formalize RBAC roles and permissions.
- Enforce org isolation in every data path.
- Implement invite and membership lifecycle.
- Record role and access changes for compliance.

## 3. Baseline
- Organization IDs exist in schema.
- Authentication exists via Replit Auth.
- Missing explicit permission enforcement and role management features.

## 4. Role Model
- `owner`: full org control including billing and role admin.
- `admin`: operational full access except ownership transfer.
- `analyst`: incident and alert operations, no org governance.
- `viewer`: read-only access.
- Optional future roles: `automation_operator`, `compliance_auditor`.

## 5. Permission Taxonomy
- Resource-action format, example:
- `incidents.read`, `incidents.write`, `incidents.close`.
- `alerts.read`, `alerts.update`, `alerts.bulk_link`.
- `reports.run`, `reports.schedule`.
- `rbac.manage`, `org.invite`, `billing.manage`.

## 6. Data Model
- `roles`
- `id`, `orgId`, `name`, `description`, `isSystem`, `createdAt`.
- `permissions`
- `id`, `key`, `description`.
- `role_permissions`
- `roleId`, `permissionId`.
- `user_roles`
- `orgId`, `userId`, `roleId`, `assignedBy`, `assignedAt`.
- `org_invites`
- `id`, `orgId`, `email`, `roleId`, `token`, `expiresAt`, `status`, `invitedBy`.

## 7. Enforcement Architecture
- Auth middleware resolves user org context and role set.
- Authorization middleware checks required permission for each route.
- Storage layer requires `orgId` in all query filters.
- Repository helpers prevent unscoped queries.

## 8. API Surface
- `POST /api/orgs/:orgId/invites`
- `GET /api/orgs/:orgId/invites`
- `POST /api/invites/:token/accept`
- `POST /api/orgs/:orgId/roles`
- `PATCH /api/orgs/:orgId/users/:userId/roles`
- `GET /api/orgs/:orgId/permissions`

## 9. UI/UX Changes
- Organization settings section:
- member list.
- invite flow.
- role assignment modal.
- permission badges for transparency.
- Contextual hiding/disable for unauthorized actions.

## 10. Audit and Compliance
- Log role changes, invitation actions, permission edits.
- Include actor, target user, previous role, new role, and timestamp.

## 11. Testing Strategy
- Unit tests for permission resolver.
- Integration tests for route-level authorization.
- Multi-tenant isolation tests with data leakage checks.

## 12. Rollout Plan
- Deploy read-only permission checks first in monitor mode.
- Collect denied action metrics.
- Switch to enforcement mode with migration guide.

## 13. Definition of Done
- RBAC checks cover all protected routes.
- Tenant isolation validated end to end.
- Org invite/member lifecycle is functional.
