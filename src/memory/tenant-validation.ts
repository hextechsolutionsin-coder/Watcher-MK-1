/**
 * Tenant Validation — Utilities for multi-tenant isolation enforcement.
 *
 * Provides tenant ID validation and cross-tenant result filtering to ensure
 * memory operations never leak data between tenants.
 */

/**
 * Error thrown when a tenant ID fails validation.
 * This is considered a programmer error and IS propagated to the caller.
 */
export class TenantValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TenantValidationError';
  }
}

/**
 * Validates a tenant ID, rejecting null, undefined, empty, or whitespace-only values.
 * Returns the trimmed tenant ID on success.
 *
 * @throws TenantValidationError if tenantId is invalid
 */
export function validateTenantId(tenantId: string | null | undefined): string {
  if (tenantId === null || tenantId === undefined) {
    throw new TenantValidationError(
      `Invalid tenant ID: tenant_id must not be ${tenantId === null ? 'null' : 'undefined'}`
    );
  }

  const trimmed = tenantId.trim();

  if (trimmed.length === 0) {
    throw new TenantValidationError(
      'Invalid tenant ID: tenant_id must not be empty or whitespace-only'
    );
  }

  return trimmed;
}

/**
 * Filters out results that belong to a different tenant than the requesting one.
 * Logs a security warning for each discarded item.
 *
 * @param results - The array of results to filter
 * @param tenantId - The requesting tenant's ID
 * @param getTenantId - Accessor function to extract the tenant_id from each result item
 * @returns Only the items belonging to the requesting tenant
 */
export function filterCrossTenantResults<T>(
  results: T[],
  tenantId: string,
  getTenantId: (item: T) => string | undefined
): T[] {
  return results.filter((item) => {
    const itemTenantId = getTenantId(item);

    if (itemTenantId !== tenantId) {
      console.error(
        `[SECURITY] Cross-tenant data detected: expected tenant_id="${tenantId}", ` +
        `got tenant_id="${itemTenantId ?? 'undefined'}". Result discarded.`
      );
      return false;
    }

    return true;
  });
}
