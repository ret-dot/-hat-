// src/core/limits.ts
export const MAX_QUANTITY_KG = 1000;

/** True only for finite numbers in (0, MAX_QUANTITY_KG]. Rejects NaN, Infinity, negatives, zero, strings. */
export function isValidQuantity(q: unknown): q is number {
  return typeof q === 'number' && Number.isFinite(q) && q > 0 && q <= MAX_QUANTITY_KG;
}