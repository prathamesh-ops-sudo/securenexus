import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  select: vi.fn(),
  insert: vi.fn(),
  update: vi.fn(),
}));

vi.mock("../db", () => ({
  db: {
    select: mocks.select,
    insert: mocks.insert,
    update: mocks.update,
  },
}));

import {
  createPlaybookChangeTicket,
  createPlaybookNotificationTemplate,
  getPlaybookChangeTickets,
  getPlaybookNotificationTemplates,
  updatePlaybookChangeTicket,
} from "../storage/playbooks";

describe("playbook workflow storage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("reads notification templates through the organization and playbook predicates", async () => {
    const templates = [{ id: "template-1", orgId: "org-a", playbookId: "playbook-1" }];
    const where = vi.fn().mockReturnValue({ orderBy: vi.fn().mockResolvedValue(templates) });
    mocks.select.mockReturnValue({ from: vi.fn().mockReturnValue({ where }) });

    await expect(getPlaybookNotificationTemplates("playbook-1", "org-a")).resolves.toEqual(templates);
    expect(where).toHaveBeenCalledTimes(1);
  });

  it("writes notification templates with both tenant identities", async () => {
    const template = { id: "template-1", orgId: "org-a", playbookId: "playbook-1" };
    const values = vi.fn().mockReturnValue({ returning: vi.fn().mockResolvedValue([template]) });
    mocks.insert.mockReturnValue({ values });

    await expect(
      createPlaybookNotificationTemplate({
        orgId: "org-a",
        playbookId: "playbook-1",
        channel: "email",
        body: "Alert {{title}}",
      }),
    ).resolves.toEqual(template);
    expect(values).toHaveBeenCalledWith(expect.objectContaining({ orgId: "org-a", playbookId: "playbook-1" }));
  });

  it("filters change tickets by tenant, playbook, and status", async () => {
    const tickets = [{ id: "ticket-1", orgId: "org-a", status: "approved" }];
    const where = vi.fn().mockReturnValue({ orderBy: vi.fn().mockResolvedValue(tickets) });
    mocks.select.mockReturnValue({ from: vi.fn().mockReturnValue({ where }) });

    await expect(getPlaybookChangeTickets("org-a", "playbook-1", "approved")).resolves.toEqual(tickets);
    expect(where).toHaveBeenCalledTimes(1);
  });

  it("writes and updates change tickets through the tenant predicate", async () => {
    const ticket = { id: "ticket-1", orgId: "org-a", playbookId: "playbook-1" };
    const insertValues = vi.fn().mockReturnValue({ returning: vi.fn().mockResolvedValue([ticket]) });
    mocks.insert.mockReturnValue({ values: insertValues });
    await expect(
      createPlaybookChangeTicket({
        id: "ticket-1",
        orgId: "org-a",
        playbookId: "playbook-1",
        playbookName: "Response",
        changeType: "network_block",
        summary: "Block host",
        changeLog: [],
      }),
    ).resolves.toEqual(ticket);
    expect(insertValues).toHaveBeenCalledWith(expect.objectContaining({ orgId: "org-a" }));

    const set = vi
      .fn()
      .mockReturnValue({ where: vi.fn().mockReturnValue({ returning: vi.fn().mockResolvedValue([ticket]) }) });
    mocks.update.mockReturnValue({ set });
    await expect(updatePlaybookChangeTicket("ticket-1", "org-a", { status: "closed" })).resolves.toEqual(ticket);
    expect(set).toHaveBeenCalledWith(expect.objectContaining({ status: "closed" }));
  });
});
