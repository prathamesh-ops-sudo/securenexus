import { db } from "../db";
import { eq, desc } from "drizzle-orm";
import {
  playbookTemplateCatalog,
  type PlaybookTemplateCatalogEntry,
  type InsertPlaybookTemplateCatalogEntry,
} from "@shared/schema";

export async function getPlaybookTemplateCatalogEntries(orgId?: string): Promise<PlaybookTemplateCatalogEntry[]> {
  if (orgId) {
    return db
      .select()
      .from(playbookTemplateCatalog)
      .where(eq(playbookTemplateCatalog.orgId, orgId))
      .orderBy(desc(playbookTemplateCatalog.createdAt));
  }
  return db.select().from(playbookTemplateCatalog).orderBy(desc(playbookTemplateCatalog.createdAt));
}

export async function getPlaybookTemplateCatalogEntry(id: string): Promise<PlaybookTemplateCatalogEntry | undefined> {
  const [row] = await db.select().from(playbookTemplateCatalog).where(eq(playbookTemplateCatalog.id, id));
  return row;
}

export async function createPlaybookTemplateCatalogEntry(
  data: InsertPlaybookTemplateCatalogEntry,
): Promise<PlaybookTemplateCatalogEntry> {
  const [row] = await db.insert(playbookTemplateCatalog).values(data).returning();
  return row;
}

export async function updatePlaybookTemplateCatalogEntry(
  id: string,
  data: Partial<PlaybookTemplateCatalogEntry>,
): Promise<PlaybookTemplateCatalogEntry | undefined> {
  const [row] = await db
    .update(playbookTemplateCatalog)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(playbookTemplateCatalog.id, id))
    .returning();
  return row;
}

export async function deletePlaybookTemplateCatalogEntry(id: string): Promise<boolean> {
  const result = await db.delete(playbookTemplateCatalog).where(eq(playbookTemplateCatalog.id, id));
  return (result.rowCount ?? 0) > 0;
}
