/**
 * Entity factory functions for correlation engine tests.
 * Provides typed Entity objects for IP, host, and user entity types.
 */
import type { Entity } from "@shared/schema";

let entityCounter = 0;

function nextId(): string {
  entityCounter++;
  return `entity-factory-${entityCounter}`;
}

/** Reset counter between test suites if needed */
export function resetEntityCounter(): void {
  entityCounter = 0;
}

function makeBaseEntity(overrides: Partial<Entity> = {}): Entity {
  const id = nextId();
  return {
    id,
    orgId: "org-test-1",
    type: "unknown",
    value: `value-${id}`,
    displayName: null,
    metadata: null,
    firstSeenAt: new Date("2026-03-25T09:00:00Z"),
    lastSeenAt: new Date("2026-03-25T10:00:00Z"),
    alertCount: 1,
    riskScore: 0,
    createdAt: new Date("2026-03-25T09:00:00Z"),
    ...overrides,
  } as Entity;
}

export function makeIPEntity(overrides: Partial<Entity> = {}): Entity {
  const counter = entityCounter + 1;
  return makeBaseEntity({
    type: "ip",
    value: `10.0.0.${counter}`,
    displayName: `IP 10.0.0.${counter}`,
    riskScore: 25,
    ...overrides,
  });
}

export function makeHostEntity(overrides: Partial<Entity> = {}): Entity {
  const counter = entityCounter + 1;
  return makeBaseEntity({
    type: "host",
    value: `workstation-${counter}`,
    displayName: `Workstation ${counter}`,
    riskScore: 10,
    ...overrides,
  });
}

export function makeUserEntity(overrides: Partial<Entity> = {}): Entity {
  const counter = entityCounter + 1;
  return makeBaseEntity({
    type: "user",
    value: `user-${counter}`,
    displayName: `User ${counter}`,
    riskScore: 5,
    ...overrides,
  });
}
