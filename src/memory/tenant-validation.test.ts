import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  TenantValidationError,
  validateTenantId,
  filterCrossTenantResults,
} from './tenant-validation.js';

describe('TenantValidationError', () => {
  it('should have correct name property', () => {
    const error = new TenantValidationError('test message');
    expect(error.name).toBe('TenantValidationError');
  });

  it('should be an instance of Error', () => {
    const error = new TenantValidationError('test');
    expect(error).toBeInstanceOf(Error);
  });

  it('should preserve the message', () => {
    const error = new TenantValidationError('something went wrong');
    expect(error.message).toBe('something went wrong');
  });
});

describe('validateTenantId', () => {
  it('should return trimmed tenant ID for valid input', () => {
    expect(validateTenantId('tenant-123')).toBe('tenant-123');
  });

  it('should trim whitespace from valid tenant IDs', () => {
    expect(validateTenantId('  tenant-123  ')).toBe('tenant-123');
  });

  it('should throw TenantValidationError for null', () => {
    expect(() => validateTenantId(null)).toThrow(TenantValidationError);
    expect(() => validateTenantId(null)).toThrow(/must not be null/);
  });

  it('should throw TenantValidationError for undefined', () => {
    expect(() => validateTenantId(undefined)).toThrow(TenantValidationError);
    expect(() => validateTenantId(undefined)).toThrow(/must not be undefined/);
  });

  it('should throw TenantValidationError for empty string', () => {
    expect(() => validateTenantId('')).toThrow(TenantValidationError);
    expect(() => validateTenantId('')).toThrow(/empty or whitespace-only/);
  });

  it('should throw TenantValidationError for whitespace-only string', () => {
    expect(() => validateTenantId('   ')).toThrow(TenantValidationError);
    expect(() => validateTenantId('\t\n')).toThrow(TenantValidationError);
  });

  it('should accept single-character tenant IDs', () => {
    expect(validateTenantId('a')).toBe('a');
  });

  it('should accept tenant IDs with special characters', () => {
    expect(validateTenantId('org_123-abc')).toBe('org_123-abc');
  });
});

describe('filterCrossTenantResults', () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {}) as unknown as ReturnType<typeof vi.spyOn>;
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  interface TestItem {
    id: string;
    tenantId: string | undefined;
  }

  const getTenantId = (item: TestItem) => item.tenantId;

  it('should return all items when all belong to the requesting tenant', () => {
    const results: TestItem[] = [
      { id: '1', tenantId: 'tenant-a' },
      { id: '2', tenantId: 'tenant-a' },
    ];

    const filtered = filterCrossTenantResults(results, 'tenant-a', getTenantId);
    expect(filtered).toHaveLength(2);
    expect(consoleErrorSpy).not.toHaveBeenCalled();
  });

  it('should discard items belonging to a different tenant', () => {
    const results: TestItem[] = [
      { id: '1', tenantId: 'tenant-a' },
      { id: '2', tenantId: 'tenant-b' },
      { id: '3', tenantId: 'tenant-a' },
    ];

    const filtered = filterCrossTenantResults(results, 'tenant-a', getTenantId);
    expect(filtered).toHaveLength(2);
    expect(filtered[0].id).toBe('1');
    expect(filtered[1].id).toBe('3');
  });

  it('should log a security warning for each discarded item', () => {
    const results: TestItem[] = [
      { id: '1', tenantId: 'tenant-b' },
      { id: '2', tenantId: 'tenant-c' },
    ];

    filterCrossTenantResults(results, 'tenant-a', getTenantId);
    expect(consoleErrorSpy).toHaveBeenCalledTimes(2);
    expect(consoleErrorSpy.mock.calls[0][0]).toContain('[SECURITY]');
    expect(consoleErrorSpy.mock.calls[1][0]).toContain('[SECURITY]');
  });

  it('should discard items with undefined tenant_id', () => {
    const results: TestItem[] = [
      { id: '1', tenantId: undefined },
      { id: '2', tenantId: 'tenant-a' },
    ];

    const filtered = filterCrossTenantResults(results, 'tenant-a', getTenantId);
    expect(filtered).toHaveLength(1);
    expect(filtered[0].id).toBe('2');
    expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
    expect(consoleErrorSpy.mock.calls[0][0]).toContain('undefined');
  });

  it('should return empty array when all items belong to other tenants', () => {
    const results: TestItem[] = [
      { id: '1', tenantId: 'tenant-x' },
      { id: '2', tenantId: 'tenant-y' },
    ];

    const filtered = filterCrossTenantResults(results, 'tenant-a', getTenantId);
    expect(filtered).toHaveLength(0);
  });

  it('should return empty array for empty input', () => {
    const filtered = filterCrossTenantResults([], 'tenant-a', getTenantId);
    expect(filtered).toHaveLength(0);
    expect(consoleErrorSpy).not.toHaveBeenCalled();
  });

  it('should include requesting tenant ID in security warning message', () => {
    const results: TestItem[] = [{ id: '1', tenantId: 'wrong-tenant' }];

    filterCrossTenantResults(results, 'my-tenant', getTenantId);
    expect(consoleErrorSpy.mock.calls[0][0]).toContain('my-tenant');
    expect(consoleErrorSpy.mock.calls[0][0]).toContain('wrong-tenant');
  });
});
