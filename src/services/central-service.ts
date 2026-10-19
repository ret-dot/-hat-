// src/services/central-service.ts
import crypto from 'node:crypto';
import { z } from 'zod';
import type {
  UserRole,
  RegistrationRecord,
  Person,
  HouseholdProfile,
  Card,
  DistributionTransaction,
  SyncBatchRequest,
  SyncBatchResponse,
  SyncBatchItemAck,
  FailureEvent,
  AuditEvent,
  ReasonCode,
} from '../core/types.js';
import { generateUuidV7 } from '../core/uuidv7.js';
import { verifyTokenPayload, hashCardId } from '../core/crypto.js';
import { validateTransition, createStateHistoryRecord } from '../core/state-machine.js';
import { CentralDatabase } from '../database/storage.js';
import { DomainError } from '../core/errors.js';
import { isValidQuantity, MAX_QUANTITY_KG } from '../core/limits.js';

const MAX_SYNC_BATCH = 500;

function isRealPastDate(s: string): boolean {
  const d = new Date(`${s}T00:00:00Z`);
  if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== s) return false; // rejects 9999-99-99, 2023-02-31
  const now = new Date();
  return d <= now && now.getUTCFullYear() - d.getUTCFullYear() <= 120;
}

// Strict Zod schema for registration (PRD 3.1 & TRD Section 3)
export const RegistrationSchema = z.object({
  first_name: z.string().min(1, 'First name is required').max(50),
  last_name: z.string().min(1, 'Last name is required').max(50),
  phone_number: z.string().regex(/^\+?[0-9]{10,15}$/, 'Valid phone number required (10-15 digits)'),
  dob: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, 'DOB must be YYYY-MM-DD')
    .refine(isRealPastDate, 'DOB must be a real date in the past'),
  family_count: z.number().int().min(1).max(30),
  yearly_income: z.number().min(0).max(1_000_000_000),
  address: z.string().min(3).max(255),
  city: z.string().min(2).max(100),
  state: z.string().min(2).max(100),
  consent_opt_in: z.boolean().refine((val) => val === true, 'Consent opt-in is required'),
});

type RegistrationWithActors = RegistrationRecord & { submitted_by?: string; verified_by?: string };

/** Keeps only the last 2 characters: works for 10-digit and 15-digit numbers alike. */
export function maskPhone(phone: string): string {
  const visible = 2;
  if (phone.length <= visible) return '*'.repeat(phone.length);
  return phone.slice(0, -visible).replace(/\d/g, '*') + phone.slice(-visible);
}

const normalizePhone = (p: string) => p.replace(/[^\d]/g, '');

const OPERATOR_ROLES = new Set(['DISTRIBUTION_OPERATOR', 'REGISTRATION_OPERATOR']);
const PRIVILEGED_ROLES = new Set(['SUPERVISOR', 'ADMIN', 'AUDITOR']);

export class CentralService {
  constructor(public readonly db: CentralDatabase) {}

  // --- Audit Logging ---
  public logAudit(actorId: string, action: string, resourceType: string, resourceId: string, details: Record<string, unknown>): void {
    const event: AuditEvent = {
      id: generateUuidV7(),
      actor_id: actorId,
      action,
      resource_type: resourceType,
      resource_id: resourceId,
      details,
      timestamp: new Date().toISOString(),
    };
    this.db.insertAuditEvent(event);
  }

  // --- Registration Workflow (PRD 3.1) ---
  public submitRegistration(payload: unknown, actorId: string, nodeId?: string): RegistrationRecord {
    const parsed = RegistrationSchema.safeParse(payload);
    if (!parsed.success) {
      throw new DomainError(`Validation failed: ${parsed.error.issues.map((e) => e.message).join(', ')}`, 400, 'ERR_101');
    }
    if (nodeId && !this.db.getNode(nodeId)) {
      throw new DomainError('Unknown distribution node', 400, 'ERR_101');
    }

    // Duplicate guard (heuristic: same phone + DOB). A national-ID check would be stronger.
    const phone = normalizePhone(parsed.data.phone_number);
    const duplicate = this.db
      .listRegistrations()
      .find((r) => normalizePhone(r.data.phone_number) === phone && r.data.dob === parsed.data.dob);
    if (duplicate) {
      throw new DomainError('A registration with this phone number and date of birth already exists', 409, 'ERR_101');
    }

    const regId = generateUuidV7();
    const now = new Date().toISOString();
    const record: RegistrationWithActors = {
      id: regId,
      status: 'SUBMITTED',
      data: parsed.data,
      node_id: nodeId || this.db.listNodes()[0]?.id,
      created_at: now,
      updated_at: now,
      submitted_by: actorId,
    };

    this.db.insertRegistration(record);
    this.logAudit(actorId, 'REGISTRATION_SUBMITTED', 'REGISTRATION', regId, { phone: maskPhone(parsed.data.phone_number) });
    return record;
  }

  public verifyRegistration(regId: string, actorId: string): RegistrationRecord {
    const reg = this.db.getRegistration(regId) as RegistrationWithActors | undefined;
    if (!reg) throw new DomainError('Registration not found', 404, 'ERR_404');
    if (reg.status !== 'SUBMITTED') {
      throw new DomainError(`Cannot verify registration in status ${reg.status}`, 409, 'ERR_401');
    }
    if (reg.submitted_by && reg.submitted_by === actorId) {
      throw new DomainError('Separation of duties: you cannot verify a registration you submitted', 403, 'ERR_403');
    }

    reg.status = 'VERIFIED';
    reg.verified_by = actorId;
    reg.updated_at = new Date().toISOString();
    this.db.updateRegistration(reg);
    this.logAudit(actorId, 'REGISTRATION_VERIFIED', 'REGISTRATION', regId, {});
    return reg;
  }

  public approveRegistration(regId: string, actorId: string): { registration: RegistrationRecord; person: Person; card: Card } {
    const reg = this.db.getRegistration(regId) as RegistrationWithActors | undefined;
    if (!reg) throw new DomainError('Registration not found', 404, 'ERR_404');
    // FIX: SUBMITTED registrations can no longer be approved directly; verification is mandatory.
    if (reg.status !== 'VERIFIED') {
      throw new DomainError(`Registration must be VERIFIED before approval (current: ${reg.status})`, 409, 'ERR_401');
    }
    if (reg.submitted_by && reg.submitted_by === actorId) {
      throw new DomainError('Separation of duties: you cannot approve a registration you submitted', 403, 'ERR_403');
    }

    const personId = generateUuidV7(); // UUIDv7 for personal_id (PRD 3.2, ID-001)
    const now = new Date().toISOString();

    const person: Person = {
      id: personId,
      first_name: reg.data.first_name,
      last_name: reg.data.last_name,
      phone_number: reg.data.phone_number,
      dob: reg.data.dob,
      created_at: now,
    };

    const household: HouseholdProfile = {
      id: generateUuidV7(),
      person_id: personId,
      family_count: reg.data.family_count,
      yearly_income: reg.data.yearly_income,
      address: reg.data.address,
      city: reg.data.city,
      state: reg.data.state,
    };

    this.db.insertPerson(person, household);

    const cardId = generateUuidV7();
    const card: Card = { id: cardId, person_id: personId, status: 'ACTIVE', issued_at: now };
    this.db.insertCard(card);

    // FIX: exactly ONE lease per card (home node). Previously legacy registrations got a lease per node,
    // multiplying the quota. Use the admin lease endpoint to move a card to another node.
    const allocatedQuota = reg.data.family_count * 10;
    this.db.setQuotaLedger({
      id: generateUuidV7(),
      card_id: cardId,
      node_id: reg.node_id ?? this.db.listNodes()[0]?.id ?? 'GLOBAL',
      allocated_qty: allocatedQuota,
      consumed_qty: 0,
      period_start: now.slice(0, 10),
    });

    reg.status = 'APPROVED';
    reg.person_id = personId;
    reg.card_id = cardId;
    reg.updated_at = now;
    this.db.updateRegistration(reg);

    this.logAudit(actorId, 'REGISTRATION_APPROVED', 'PERSON', personId, { card_id: cardId, quota: allocatedQuota });

    return { registration: reg, person, card };
  }

  // --- Portal & Autofill (PRD 3.3, PORTAL-001 to PORTAL-004) ---
  public lookupPerson(personId: string, callerRole: UserRole, callerId: string): Record<string, unknown> {
    const role = callerRole as string;
    // FIX: fail closed. Unknown roles used to fall through to the full-PII branch.
    if (role !== 'BENEFICIARY' && !OPERATOR_ROLES.has(role) && !PRIVILEGED_ROLES.has(role)) {
      throw new DomainError('Forbidden', 403, 'ERR_403');
    }

    const person = this.db.getPersonById(personId);
    if (!person) throw new DomainError('Person not found', 404, 'ERR_404');

    const household = this.db.getHouseholdByPersonId(personId);
    const card = this.db.getCardByPersonId(personId);
    const ledger = card ? this.db.getQuotaLedger(card.id) : undefined;

    this.logAudit(callerId, 'PERSON_LOOKUP', 'PERSON', personId, { role });

    if (role === 'BENEFICIARY') {
      return {
        id: person.id,
        first_name: person.first_name,
        last_name: person.last_name,
        masked_phone: maskPhone(person.phone_number), // FIX: previously a no-op for 10-digit numbers
        card_id: card?.id,
        card_status: card?.status,
        quota_available: ledger ? ledger.allocated_qty - ledger.consumed_qty : 0,
      };
    }

    if (OPERATOR_ROLES.has(role)) {
      return {
        id: person.id,
        full_name: `${person.first_name} ${person.last_name}`,
        phone_number: maskPhone(person.phone_number), // least privilege: operators don't need the full number
        family_count: household?.family_count,
        city: household?.city,
        state: household?.state,
        card_id: card?.id,
        card_status: card?.status,
        quota_allocated: ledger?.allocated_qty,
        quota_consumed: ledger?.consumed_qty,
        quota_available: ledger ? ledger.allocated_qty - ledger.consumed_qty : 0,
        yearly_income: 'RESTRICTED_ACCESS',
      };
    }

    if (callerRole === 'SUPERVISOR' || callerRole === 'ADMINISTRATOR' || callerRole === 'AUDITOR') {
      return {
        id: person.id,
        first_name: person.first_name,
        last_name: person.last_name,
        phone_number: person.phone_number,
        dob: person.dob,
        household,
        card,
        quota_ledger: ledger,
      };
    }

    throw new Error('Insufficient role to access person records');
  }

  public autofillTemplate(personId: string, templateType: 'DISTRIBUTION_RECEIPT' | 'APPLICATION_FORM', callerRole: UserRole, callerId: string): Record<string, unknown> {
    const data = this.lookupPerson(personId, callerRole, callerId);
    if (templateType === 'DISTRIBUTION_RECEIPT') {
      return {
        template: 'DISTRIBUTION_RECEIPT',
        beneficiary_id: data.id,
        beneficiary_name: (data.full_name as string) || `${data.first_name} ${data.last_name}`,
        card_id: data.card_id,
        available_quota_kg: data.quota_available,
        timestamp: new Date().toISOString(),
        issuer_agent: callerId,
      };
    }

    return {
      template: 'APPLICATION_FORM',
      beneficiary_id: data.id,
      first_name: data.first_name,
      last_name: data.last_name,
      family_count: (data.household as HouseholdProfile)?.family_count ?? data.family_count,
      address: (data.household as HouseholdProfile)?.address ?? 'REDACTED',
      status: 'VERIFIED_ACTIVE',
    };
  }

  // --- Online Distribution Transaction (TXN-001, Idempotent) ---
  private rememberRequest(scope: string, fingerprint: string, status: number, response: unknown) {
    this.db.setIdempotency(scope, status, { fingerprint, response });
  }

  public processOnlineTransaction(params: {
    cardId: string;
    lotId: string;
    nodeId: string;
    quantity: number;
    idempotencyKey: string;
    actorId: string;
  }): { status: number; body: unknown } {
    // FIX: reject NaN / Infinity / negative / zero / absurd quantities before touching any ledger.
    if (!isValidQuantity(params.quantity)) {
      return { status: 400, body: { code: 'ERR_101', message: `Quantity must be a positive number up to ${MAX_QUANTITY_KG} kg` } };
    }

    // FIX: idempotency is scoped per caller and bound to the request body.
    const scope = `txn:${params.actorId}:${params.idempotencyKey}`;
    const fingerprint = crypto
      .createHash('sha256')
      .update(JSON.stringify([params.cardId, params.lotId, params.nodeId, params.quantity]))
      .digest('hex');
    const cached = this.db.getIdempotency(scope);
    if (cached) {
      const stored = cached.body as { fingerprint?: string; response?: unknown } | undefined;
      if (stored?.fingerprint !== fingerprint) {
        return { status: 422, body: { code: 'ERR_101', message: 'Idempotency-Key was already used with a different request' } };
      }
      return { status: cached.status, body: stored.response };
    }

    const card = this.db.listCards().find((c) => c.id === params.cardId);
    if (!card || card.status !== 'ACTIVE') {
      return { status: 404, body: { code: 'ERR_404', message: 'Card not found or not active' } };
    }
    if (!this.db.getNode(params.nodeId)) {
      return { status: 400, body: { code: 'ERR_101', message: 'Unknown distribution node' } };
    }

    const txnId = generateUuidV7();
    const now = new Date().toISOString();

    const txn: DistributionTransaction = {
      id: txnId,
      card_id: params.cardId,
      node_id: params.nodeId,
      lot_id: params.lotId,
      quantity: params.quantity,
      state: 'ATTEMPT',
      idempotency_key: params.idempotencyKey,
      created_at: now,
      updated_at: now,
    };

    this.db.insertStateHistory(createStateHistoryRecord(txnId, 'INITIAL', 'ATTEMPT', params.actorId));

    const deduction = this.db.atomicDeductQuota(params.cardId, params.nodeId, params.lotId, params.quantity);
    if (!deduction.success) {
      const reasonCode: ReasonCode = deduction.reason === 'CARD_QUOTA_EXHAUSTED' ? 'ERR_201' : 'ERR_202';
      validateTransition(txn.state, 'FAIL_REASON');
      txn.state = 'FAIL_REASON';
      txn.failure_reason = reasonCode;
      this.db.insertTransaction(txn);
      this.db.insertStateHistory(createStateHistoryRecord(txnId, 'ATTEMPT', 'FAIL_REASON', params.actorId, reasonCode));

      const failureEvent: FailureEvent = {
        event_id: generateUuidV7(),
        txn_id: txnId,
        type: 'TXN_FAILURE',
        code: reasonCode,
        node_id: params.nodeId,
        timestamp: now,
        retryable: false,
        metadata: { requested_quantity: params.quantity, reason: deduction.reason },
      };
      this.db.insertFailureEvent(failureEvent);

      const resp = {
        success: false,
        code: reasonCode,
        message: deduction.reason === 'CARD_QUOTA_EXHAUSTED' ? 'Card quota exhausted' : 'Lot cap exhausted',
        transaction: txn,
      };
      this.rememberRequest(scope, fingerprint, 409, resp);
      return { status: 409, body: resp };
    }

    validateTransition(txn.state, 'PROVISIONAL_ISSUE');
    txn.state = 'PROVISIONAL_ISSUE';
    this.db.insertStateHistory(createStateHistoryRecord(txnId, 'ATTEMPT', 'PROVISIONAL_ISSUE', params.actorId));

    validateTransition(txn.state, 'RECONCILED');
    txn.state = 'RECONCILED';
    this.db.insertStateHistory(createStateHistoryRecord(txnId, 'PROVISIONAL_ISSUE', 'RECONCILED', params.actorId));

    txn.updated_at = new Date().toISOString();
    this.db.insertTransaction(txn);

    const successResp = { success: true, message: 'Transaction processed and reconciled successfully', transaction: txn };
    this.rememberRequest(scope, fingerprint, 201, successResp);
    return { status: 201, body: successResp };
  }

  // --- Batch Sync & Reconciliation (reconciliation.md, api-spec.yaml) ---
  public async reconcileBatch(nodeId: string, batch: SyncBatchRequest): Promise<SyncBatchResponse> {
    const node = this.db.getNode(nodeId);
    if (!node) throw new DomainError('Node not registered', 404, 'ERR_404');
    if (!Array.isArray(batch?.tokens) || batch.tokens.length > MAX_SYNC_BATCH) {
      throw new DomainError(`Batch must contain at most ${MAX_SYNC_BATCH} tokens`, 400, 'ERR_101');
    }

    const items: SyncBatchItemAck[] = [];
    let accepted = 0;
    let rejected = 0;
    let duplicate = 0;
    let conflict = 0;
    const manualReview = 0;

    // Resolve cards from the signed `sub` (hash of the full card id). `qid` only holds a truncated prefix.
    let cardBySub: Map<string, string> | undefined;
    const resolveCard = (sub: string): string | undefined => {
      cardBySub ??= new Map(this.db.listCards().map((c) => [hashCardId(c.id), c.id] as const));
      return cardBySub.get(sub);
    };

    const reject = (token: SyncBatchRequest['tokens'][number], code: ReasonCode, message: string, type: 'CRYPTO_FAILURE' | 'TXN_FAILURE', metadata: Record<string, unknown> = {}) => {
      rejected += 1;
      this.db.insertFailureEvent({
        event_id: generateUuidV7(),
        txn_id: token.payload.tid,
        type,
        code,
        node_id: nodeId,
        timestamp: new Date().toISOString(),
        retryable: false,
        metadata,
      });
      items.push({ token_id: token.id, txn_id: token.txn_id, outcome: 'REJECTED', reason_code: code, message });
    };

    const conflictWith = (token: SyncBatchRequest['tokens'][number], code: ReasonCode, message: string, metadata: Record<string, unknown> = {}) => {
      conflict += 1;
      this.db.insertFailureEvent({
        event_id: generateUuidV7(),
        txn_id: token.payload.tid,
        type: 'TXN_FAILURE',
        code,
        node_id: nodeId,
        timestamp: new Date().toISOString(),
        retryable: false,
        metadata,
      });
      items.push({ token_id: token.id, txn_id: token.txn_id, outcome: 'CONFLICT', reason_code: code, message });
    };

    for (const token of batch.tokens) {
      const p = token.payload;

      // 1. FIX (replay): every unsigned envelope field must equal its signed counterpart, and the token
      //    must belong to the node that is syncing. Dedup below uses ONLY signed values.
      if (
        token.txn_id !== p.tid || token.nonce !== p.n || token.counter !== p.c ||
        token.key_id !== p.kid || p.nid !== nodeId || p.v !== 1 || p.unit !== 'kg' ||
        !isValidQuantity(p.qty)
      ) {
        reject(token, 'ERR_301', 'Token envelope does not match signed payload', 'CRYPTO_FAILURE', { reason: 'envelope mismatch' });
        continue;
      }

      // 2. Cryptographic Signature Verification (Ed25519), before any state lookups
      const isSigValid = await verifyTokenPayload(p, token.signature, node.public_key);
      if (!isSigValid) {
        reject(token, 'ERR_301', 'Invalid cryptographic signature', 'CRYPTO_FAILURE', { reason: 'Ed25519 signature mismatch or forged payload' });
        continue;
      }

      // ---- No `await` below this line: the check-and-commit sequence is atomic within the process ----

      // 3. Duplicate / replay check on SIGNED nonce + txn id
      if (this.db.isNonceUsed(p.n) || this.db.getTransaction(p.tid)?.state === 'RECONCILED') {
        duplicate += 1;
        items.push({
          token_id: token.id,
          txn_id: token.txn_id,
          outcome: 'DUPLICATE',
          message: 'Nonce or transaction already reconciled. Idempotently acknowledged.',
        });
        continue;
      }

      // 4. Expiry Check (Test Plan 19)
      const nowSec = Math.floor(Date.now() / 1000);
      if (p.exp < nowSec) {
        reject(token, 'ERR_402', 'Provisional token expired prior to reconciliation', 'TXN_FAILURE', { exp: p.exp, now: nowSec });
        continue;
      }

      // 5. Lot, card and existing-transaction checks
      if (!this.db.getLot(p.lid)) {
        conflictWith(token, 'ERR_401', 'Lot referenced by token does not exist in central ledger');
        continue;
      }
      const cardId = resolveCard(p.sub);
      if (!cardId) {
        conflictWith(token, 'ERR_401', 'Card referenced by token does not exist in central ledger');
        continue;
      }
      if (this.db.getTransaction(p.tid)) {
        conflictWith(token, 'ERR_401', 'Transaction id already exists in a non-reconciled state');
        continue;
      }

      // 6. FIX (accounting): charge the central card ledger and lot. Previously offline issuance was never
      //    deducted, so central quotas could be exceeded indefinitely.
      const deduction = this.db.atomicDeductQuota(cardId, nodeId, p.lid, p.qty);
      if (!deduction.success) {
        const code: ReasonCode = deduction.reason === 'CARD_QUOTA_EXHAUSTED' ? 'ERR_201' : 'ERR_202';
        conflictWith(token, code, 'Offline issuance exceeds the central quota/lot ledger. Flagged for review', {
          requested_quantity: p.qty,
          reason: deduction.reason,
        });
        continue;
      }

      const nowIso = new Date().toISOString();
      const txn: DistributionTransaction = {
        id: p.tid,
        card_id: cardId, // full card id (was a truncated 8-char prefix)
        node_id: nodeId,
        lot_id: p.lid,
        quantity: p.qty,
        state: 'RECONCILED',
        idempotency_key: p.n,
        created_at: nowIso,
        updated_at: nowIso,
      };
      this.db.insertTransaction(txn);
      this.db.insertStateHistory(createStateHistoryRecord(p.tid, 'PROVISIONAL_ISSUE', 'RECONCILED', `node:${nodeId}`));

      this.db.insertProvisionalToken(token);
      this.db.markNonceUsed(p.n, token.id);

      accepted += 1;
      items.push({
        token_id: token.id,
        txn_id: token.txn_id,
        outcome: 'ACCEPTED',
        message: 'Successfully reconciled and committed to central ledger',
      });
    }

    node.last_heartbeat = new Date().toISOString();
    node.status = 'ONLINE';
    node.outbox_depth = Math.max(0, node.outbox_depth - (accepted + duplicate));
    this.db.updateNode(node);

    this.logAudit(`node:${nodeId}`, 'BATCH_SYNC_PROCESSED', 'SYNC_BATCH', batch.batch_id, {
      total: batch.tokens.length,
      accepted,
      rejected,
      duplicate,
      conflict,
      manualReview,
    });

    return {
      batch_id: batch.batch_id,
      processed_count: batch.tokens.length,
      accepted_count: accepted,
      rejected_count: rejected,
      duplicate_count: duplicate,
      conflict_count: conflict,
      manual_review_count: manualReview,
      items,
    };
  }

  // --- Metrics & Analytics (failure-catalog.md) ---
  public getMetrics(): {
    totalAttempts: number;
    failureEventsCount: number;
    failureRate: number;
    fallbackCount: number;
    fallbackRate: number;
    syncBacklog: number;
    alertStatus: { invalidSigAlert: boolean; backlogAlert: boolean };
    failureBreakdown: Record<string, number>;
  } {
    const txns = this.db.listTransactions();
    const failures = this.db.listFailureEvents();
    const nodes = this.db.listNodes();

    const attemptsCount = txns.length;
    const failureCount = failures.length;
    const failureRate = attemptsCount > 0 ? Number((failureCount / attemptsCount).toFixed(4)) : 0;

    const fallbackCount = txns.filter((t) => t.state === 'FALLBACK_AUTH').length;
    const failReasonCount = txns.filter((t) => t.state === 'FAIL_REASON').length;
    const fallbackRate = failReasonCount > 0 ? Number((fallbackCount / failReasonCount).toFixed(4)) : 0;

    const syncBacklog = nodes.reduce((sum, n) => sum + (n.outbox_depth || 0), 0);

    const sigFailures = failures.filter((f) => f.code === 'ERR_301').length;
    const invalidSigAlert = failureCount > 0 ? sigFailures / failureCount > 0.05 : false;
    const backlogAlert = syncBacklog > 10000;

    const breakdown: Record<string, number> = {};
    for (const f of failures) {
      breakdown[f.code] = (breakdown[f.code] || 0) + 1;
    }

    return {
      totalAttempts: attemptsCount,
      failureEventsCount: failureCount,
      failureRate,
      fallbackCount,
      fallbackRate,
      syncBacklog,
      alertStatus: { invalidSigAlert, backlogAlert },
      failureBreakdown: breakdown,
    };
  }
}