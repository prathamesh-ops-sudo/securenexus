import type { Request, Response, NextFunction } from "express";

export const PAGINATION_CONTRACT = {
  defaultOffset: 0,
  defaultLimit: 50,
  maxLimit: 200,
  maxOffset: 1_000_000,
  defaultSortOrder: "desc" as const,
  defaultSortColumn: "createdAt",
  supportedSortOrders: ["asc", "desc"] as const,
  supportedFilterOperators: ["eq", "ne", "gt", "gte", "lt", "lte", "in", "contains", "startsWith"] as const,
} as const;

export type SortOrder = "asc" | "desc";
export type FilterOperator = (typeof PAGINATION_CONTRACT.supportedFilterOperators)[number];

export interface StandardPaginationParams {
  offset: number;
  limit: number;
  sortBy: string;
  sortOrder: SortOrder;
  search?: string;
}

export interface PaginationMeta {
  offset: number;
  limit: number;
  total: number;
  hasMore: boolean;
  [key: string]: unknown;
}

export function parseStandardPagination(
  query: Record<string, unknown>,
  allowedSortFields?: string[],
): StandardPaginationParams {
  const offset = Math.max(
    0,
    Math.min(Number(query.offset ?? PAGINATION_CONTRACT.defaultOffset) || 0, PAGINATION_CONTRACT.maxOffset),
  );
  const rawLimit = Number(query.limit ?? PAGINATION_CONTRACT.defaultLimit) || PAGINATION_CONTRACT.defaultLimit;
  const limit = Math.min(Math.max(1, rawLimit), PAGINATION_CONTRACT.maxLimit);
  const sortOrder: SortOrder = query.sortOrder === "asc" ? "asc" : PAGINATION_CONTRACT.defaultSortOrder;

  let sortBy: string = PAGINATION_CONTRACT.defaultSortColumn;
  if (typeof query.sortBy === "string" && query.sortBy.length > 0 && query.sortBy.length <= 64) {
    if (!allowedSortFields || allowedSortFields.includes(query.sortBy)) {
      sortBy = query.sortBy;
    }
  }

  const search =
    typeof query.search === "string" && query.search.trim().length > 0 ? query.search.trim().slice(0, 2000) : undefined;

  return { offset, limit, sortBy, sortOrder, search };
}

export function buildPaginationMeta(
  offset: number,
  limit: number,
  total: number,
  extra?: Record<string, unknown>,
): PaginationMeta {
  return {
    offset,
    limit,
    total,
    hasMore: offset + limit < total,
    ...extra,
  };
}

export function paginationContractDoc(): Record<string, unknown> {
  return {
    description: "SecureNexus Pagination Contract v1",
    offsetBased: {
      defaultOffset: PAGINATION_CONTRACT.defaultOffset,
      defaultLimit: PAGINATION_CONTRACT.defaultLimit,
      maxLimit: PAGINATION_CONTRACT.maxLimit,
      maxOffset: PAGINATION_CONTRACT.maxOffset,
    },
    sorting: {
      defaultSortColumn: PAGINATION_CONTRACT.defaultSortColumn,
      defaultSortOrder: PAGINATION_CONTRACT.defaultSortOrder,
      supportedOrders: [...PAGINATION_CONTRACT.supportedSortOrders],
    },
    filtering: {
      supportedOperators: [...PAGINATION_CONTRACT.supportedFilterOperators],
      searchBehavior:
        "Full-text search across title, description, and domain-specific fields. Case-insensitive. Maximum 2000 characters.",
    },
    responseEnvelope: {
      shape: "{ data: T[], meta: { offset, limit, total, hasMore, ...filters }, errors: null }",
      errorShape: "{ data: null, meta: {}, errors: [{ code: string, message: string, details?: unknown }] }",
    },
  };
}
