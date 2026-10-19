// src/api/schemas.ts
import { z } from 'zod';
import { MAX_QUANTITY_KG } from '../core/limits.js';

const id = z.string().trim().min(1).max(128).regex(/^[A-Za-z0-9._:-]+$/, 'invalid identifier');

/** Accepts a JSON number or a plain decimal string; rejects NaN, Infinity, negatives, zero, "1e9", booleans, null. */
const quantity = z
  .union([z.number(), z.string().regex(/^\d{1,7}(\.\d{1,3})?$/).transform(Number)])
  .pipe(z.number().positive().max(MAX_QUANTITY_KG));

export const idempotencyKeySchema = z.string().regex(/^[A-Za-z0-9_.:-]{8,128}$/, 'invalid Idempotency-Key');

export const loginSchema = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(256),
});

export const transactionSchema = z.object({
  card_id: id,
  lot_id: id,
  node_id: id.optional(),
  quantity,
});

export const issueSchema = z.object({
  card_id: id,
  lot_id: id,
  grant_id: id.optional(),
  quantity,
  allow_fallback: z.boolean().optional(),
});

export const leaseSchema = z.object({ card_id: id, node_id: id, quantity });

export const lotSchema = z.object({
  name: z.string().trim().min(1).max(100),
  grain_type: z.string().trim().min(1).max(50),
  total_quantity: z
    .union([z.number(), z.string().regex(/^\d{1,10}(\.\d{1,3})?$/).transform(Number)])
    .pipe(z.number().positive().max(1_000_000_000)),
});

// Field ORDER matters: it matches the order the edge node signs the payload in.
const tokenPayload = z.strictObject({
  v: z.literal(1),
  tid: id,
  nid: id,
  lid: id,
  gid: id,
  qid: z.string().min(1).max(64),
  sub: z.string().min(1).max(256),
  n: z.string().regex(/^[0-9a-f]{32}$/),
  c: z.number().int().nonnegative(),
  qty: z.number().positive().max(MAX_QUANTITY_KG),
  unit: z.literal('kg'),
  iat: z.number().int().nonnegative(),
  exp: z.number().int().nonnegative(),
  kid: z.string().min(1).max(64),
});

const signedToken = z.strictObject({
  id,
  txn_id: id,
  payload: tokenPayload,
  signature: z.string().min(1).max(512),
  key_id: z.string().min(1).max(64),
  nonce: z.string().regex(/^[0-9a-f]{32}$/),
  counter: z.number().int().nonnegative(),
  created_at: z.string().max(40),
});

export const syncBatchSchema = z.strictObject({
  batch_id: id,
  tokens: z.array(signedToken).min(1).max(100),
});