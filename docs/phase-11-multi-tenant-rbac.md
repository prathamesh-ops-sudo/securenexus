# Phase 11: Multi-Tenant and RBAC Detailed Report

## Goal
Enforce strict tenant isolation and role-based authorization across API and UI.

## What Must Be Fixed
- Role system and route-level permission checks are incomplete.

## Required Work
- Define roles: owner, admin, analyst, viewer.
- Define permission matrix per resource/action.
- Add invite/member lifecycle and role assignment flows.
- Add authorization middleware and scoped repository helpers.

## Data and API Scope
- Tables: `roles`, `permissions`, `role_permissions`, `user_roles`, `org_invites`.
- APIs: invite/create/accept/list, role assignment, permission listing.

## UI Scope
- Org settings: members, invitations, roles.
- Gate unauthorized actions in page-level controls.

## Testing
- Permission resolver unit tests.
- Cross-tenant leakage integration tests.

## Definition of Done
- All protected endpoints enforce role permissions with zero cross-tenant leakage.
