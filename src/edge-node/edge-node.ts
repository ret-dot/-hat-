// src/edge-node/edge-node.ts
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type {
  SignedProvisionalToken,
  ProvisionalTokenPayload,
  SyncBatchRequest,
  SyncBatchResponse,
  ReasonCode,
  DistributionTransaction,
  TxnState,
} from '../core/types.js';
import { generateUuidV7 } from '../core/uuidv7.js';
import { hashCardId, signTokenPayload } from '../core/crypto.js';
import { validateTransition } from '../core/state-machine.js';
import { isValidQuantity, MAX_QUANTITY_KG } from '../core/limits.js';

export interface EdgeNodeConfig {
  nodeId: string;
  nodeName: string;
  privateKeyHex: string;
  publicKeyHex: string;
  dataDir: string;
  /** Total kg a supervisor may override per card beyond its lease (default 10). Tune to policy. */
  maxFallbackQtyPerCard?: number;
}

export interface EdgeOutboxItem {
  id: string;
  token: SignedProvisionalToken;
  status: 'PENDING' | 'SYNCED' | 'FAILED';
  attempts: number;
  created_at: string;
}

export interface EdgeNodeState {
  counter: number;
  localQuotas: Record<string, { allocated: number; consumed: number }>;
  activeGrants: Record<string, { maxQuantity: number; consumed: number; expiresAt: number }>;
  outbox: EdgeOutboxItem[];
  transactions: DistributionTransaction[];
  /** idempotency key -> request fingerprint + resulting transaction */
  idempotency: Record<string, { fingerprint: string; txnId: string }>;
  /** total kg issued per card through supervisor override */
  fallbackUsed: Record<string, number>;
}

const MAX_IDEMPOTENCY_ENTRIES = 2000;
const SAFE_ID = /^[A-Za-z0-9_-]+$/;

export class EdgeDistributionNode {
  public readonly config: EdgeNodeConfig;
  private stateFile: string;
  private state: EdgeNodeState;
  public isOnline: boolean = true;

  constructor(config: EdgeNodeConfig) {
    if (!SAFE_ID.test(config.nodeId)) throw new Error('Invalid node id');
    this.config = config;
    this.stateFile = path.join(config.dataDir, `node_${config.nodeId}_state.json`);
    this.state = this.loadState();
  }

  private freshState(): EdgeNodeState {
    return { counter: 1000, localQuotas: {}, activeGrants: {}, outbox: [], transactions: [], idempotency: {}, fallbackUsed: {} };
  }

  private loadState(): EdgeNodeState {
    if (!fs.existsSync(this.config.dataDir)) {
      fs.mkdirSync(this.config.dataDir, { recursive: true });
    }
    if (!fs.existsSync(this.stateFile)) return this.freshState();

    try {
      const raw = fs.readFileSync(this.stateFile, 'utf-8');
      return { ...this.freshState(), ...JSON.parse(raw) }; // defaults fill fields from older state files
    } catch {
      // FIX: never silently restart from scratch; that would reset the token counter and drop the unsent outbox.
      const quarantine = `${this.stateFile}.corrupt-${Date.now()}`;
      try { fs.renameSync(this.stateFile, quarantine); } catch { /* ignore */ }
      throw new Error(
        `Edge node ${this.config.nodeId}: state file is corrupt and was moved to ${quarantine}. ` +
        'Restore from backup or reconcile manually before restarting.',
      );
    }
  }

  private persistState(): void {
    // FIX: atomic write (temp file + rename) so a crash cannot leave a half-written state file.
    const tmp = `${this.stateFile}.${process.pid}.tmp`;
    try {
      fs.writeFileSync(tmp, JSON.stringify(this.state, null, 2), { encoding: 'utf-8', mode: 0o600 });
      fs.renameSync(tmp, this.stateFile);
    } catch (e) {
      console.error(`Edge node ${this.config.nodeId} failed to persist state:`, e);
      throw e; // an un-persisted issuance must not be reported as successful
    }
  }

  public getCounter(): number {
    return this.state.counter;
  }

  public getOutboxDepth(): number {
    return this.state.outbox.filter((item) => item.status === 'PENDING').length;
  }

  /** Adds to the existing lease (used for brand new cards). */
  public allocateLocalLease(cardId: string, quantity: number): void {
    if (!isValidQuantity(quantity)) throw new Error('Invalid lease quantity');
    const existing = this.state.localQuotas[cardId] || { allocated: 0, consumed: 0 };
    existing.allocated += quantity;
    this.state.localQuotas[cardId] = existing;
    this.persistState();
  }

  /** Sets the lease to an absolute value while PRESERVING what the card already consumed. */
  public setLocalLease(cardId: string, allocated: number): void {
    if (!isValidQuantity(allocated)) throw new Error('Invalid lease quantity');
    const existing = this.state.localQuotas[cardId] || { allocated: 0, consumed: 0 };
    existing.allocated = allocated;
    this.state.localQuotas[cardId] = existing;
    this.persistState();
  }

  public getLocalCardQuota(cardId: string): { allocated: number; consumed: number; available: number } {
    const quota = this.state.localQuotas[cardId] || { allocated: 0, consumed: 0 };
    return {
      allocated: quota.allocated,
      consumed: quota.consumed,
      available: Math.max(0, quota.allocated - quota.consumed),
    };
  }

  public setGrant(grantId: string, maxQuantity: number, expiresAt: number): void {
    this.state.activeGrants[grantId] = { maxQuantity, consumed: 0, expiresAt };
    this.persistState();
  }

  private remember(key: string, fingerprint: string, txnId: string): void {
    this.state.idempotency[key] = { fingerprint, txnId };
    const keys = Object.keys(this.state.idempotency);
    if (keys.length > MAX_IDEMPOTENCY_ENTRIES) {
      for (const k of keys.slice(0, keys.length - MAX_IDEMPOTENCY_ENTRIES)) delete this.state.idempotency[k];
    }
  }

  /**
   * Distribute Grain Provisionally (Online or Offline).
   * Executes the 5-state machine: ATTEMPT -> PROVISIONAL_ISSUE or FAIL_REASON -> FALLBACK_AUTH
   */
  public async issueProvisionalGrain(params: {
    cardId: string;
    lotId: string;
    grantId: string;
    quantity: number;
    idempotencyKey: string;
    allowFallback?: boolean;
    /** Authenticated supervisor id. REQUIRED when allowFallback is true. */
    fallbackAuthorizedBy?: string;
  }): Promise<{
    transaction: DistributionTransaction;
    token?: SignedProvisionalToken;
    state: TxnState;
    error?: string;
    reasonCode?: ReasonCode;
  }> {
    // FIX: NaN / Infinity / negative / zero quantities used to pass every comparison below.
    if (!isValidQuantity(params.quantity)) {
      throw new Error(`Quantity must be a positive number up to ${MAX_QUANTITY_KG} kg`);
    }
    if (params.allowFallback && !params.fallbackAuthorizedBy) {
      throw new Error('Fallback override requires an authenticated supervisor');
    }

    // FIX: idempotent replay (double-click / network retry must not dispense twice).
    const fingerprint = JSON.stringify([params.cardId, params.lotId, params.grantId, params.quantity, Boolean(params.allowFallback)]);
    const prior = this.state.idempotency[params.idempotencyKey];
    if (prior) {
      if (prior.fingerprint !== fingerprint) throw new Error('Idempotency-Key was already used with a different request');
      const priorTxn = this.state.transactions.find((t) => t.id === prior.txnId);
      if (priorTxn) {
        const priorToken = this.state.outbox.find((o) => o.token.txn_id === priorTxn.id)?.token;
        return priorTxn.state === 'FAIL_REASON'
          ? { transaction: priorTxn, state: priorTxn.state, error: 'Request previously failed', reasonCode: priorTxn.failure_reason }
          : { transaction: priorTxn, token: priorToken, state: priorTxn.state };
      }
    }

    const txnId = generateUuidV7();
    const nowIso = new Date().toISOString();

    const txn: DistributionTransaction = {
      id: txnId,
      card_id: params.cardId,
      node_id: this.config.nodeId,
      lot_id: params.lotId,
      quantity: params.quantity,
      state: 'ATTEMPT',
      idempotency_key: params.idempotencyKey,
      created_at: nowIso,
      updated_at: nowIso,
    };

    // Check grant
    const grant = this.state.activeGrants[params.grantId];
    const nowSec = Math.floor(Date.now() / 1000);
    if (!grant || grant.expiresAt < nowSec || grant.consumed + params.quantity > grant.maxQuantity) {
      validateTransition(txn.state, 'FAIL_REASON');
      txn.state = 'FAIL_REASON';
      txn.failure_reason = 'ERR_202'; // Lot cap exhausted
      this.state.transactions.push(txn);
      this.remember(params.idempotencyKey, fingerprint, txnId);
      this.persistState();
      return { transaction: txn, state: txn.state, error: 'Lot cap exhausted or grant expired', reasonCode: 'ERR_202' };
    }

    // Check local quota lease
    const localQuota = this.getLocalCardQuota(params.cardId);
    let usedFallback = false;
    if (localQuota.available < params.quantity) {
      validateTransition(txn.state, 'FAIL_REASON');
      txn.state = 'FAIL_REASON';
      txn.failure_reason = 'ERR_201'; // Card quota exhausted

      const cap = this.config.maxFallbackQtyPerCard ?? 10;
      const alreadyOverridden = this.state.fallbackUsed[params.cardId] ?? 0;

      if (params.allowFallback && alreadyOverridden + params.quantity <= cap) {
        validateTransition(txn.state, 'FALLBACK_AUTH');
        txn.state = 'FALLBACK_AUTH';
        txn.fallback_reason = `Supervisor offline override by ${params.fallbackAuthorizedBy}`;
        usedFallback = true;
      } else {
        this.state.transactions.push(txn);
        this.remember(params.idempotencyKey, fingerprint, txnId);
        this.persistState();
        return {
          transaction: txn,
          state: txn.state,
          error: params.allowFallback ? 'Supervisor override allowance exhausted for this card' : 'Card quota exhausted on local lease',
          reasonCode: txn.failure_reason,
        };
      }
    }

    const targetState: TxnState = 'PROVISIONAL_ISSUE';
    validateTransition(txn.state, targetState);
    txn.state = targetState;

    // Deduct local grant and card lease
    grant.consumed += params.quantity;
    if (this.state.localQuotas[params.cardId]) {
      this.state.localQuotas[params.cardId].consumed += params.quantity;
    }
    if (usedFallback) {
      this.state.fallbackUsed[params.cardId] = (this.state.fallbackUsed[params.cardId] ?? 0) + params.quantity;
    }

    this.state.counter += 1;
    const currentCounter = this.state.counter;

    // Canonical token payload (field order is part of the signed format; keep in sync with schemas.ts)
    const payload: ProvisionalTokenPayload = {
      v: 1,
      tid: txnId,
      nid: this.config.nodeId,
      lid: params.lotId,
      gid: params.grantId,
      qid: `quota_${params.cardId.slice(0, 8)}`,
      sub: hashCardId(params.cardId),
      n: crypto.randomBytes(16).toString('hex'),
      c: currentCounter,
      qty: Number(params.quantity.toFixed(2)),
      unit: 'kg',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour validity
      kid: `key_${this.config.nodeId.slice(0, 8)}`,
    };

    const signature = await signTokenPayload(payload, this.config.privateKeyHex);

    const signedToken: SignedProvisionalToken = {
      id: generateUuidV7(),
      txn_id: txnId,
      payload,
      signature,
      key_id: payload.kid,
      nonce: payload.n,
      counter: payload.c,
      created_at: nowIso,
    };

    this.state.outbox.push({ id: generateUuidV7(), token: signedToken, status: 'PENDING', attempts: 0, created_at: nowIso });
    this.state.transactions.push(txn);
    this.remember(params.idempotencyKey, fingerprint, txnId);
    this.persistState();

    return { transaction: txn, token: signedToken, state: txn.state };
  }

  /** Generates a sync batch of pending provisional tokens. */
  public generateSyncBatch(maxItems = 100): SyncBatchRequest | null {
    const pending = this.state.outbox.filter((item) => item.status === 'PENDING').slice(0, maxItems);
    if (pending.length === 0) return null;
    return { batch_id: generateUuidV7(), tokens: pending.map((item) => item.token) };
  }

  /** Processes ACK response from central server. */
  public processSyncResponse(response: SyncBatchResponse): void {
    for (const ack of response.items) {
      const item = this.state.outbox.find((o) => o.token.id === ack.token_id || o.token.txn_id === ack.txn_id);
      if (item) {
        if (ack.outcome === 'ACCEPTED' || ack.outcome === 'DUPLICATE') {
          item.status = 'SYNCED';
        } else if (ack.outcome === 'REJECTED' || ack.outcome === 'CONFLICT') {
          item.status = 'FAILED';
        }
      }

      const txn = this.state.transactions.find((t) => t.id === ack.txn_id);
      if (txn && ack.outcome === 'ACCEPTED') {
        txn.state = 'RECONCILED';
      }
    }
    this.state.outbox = this.state.outbox.filter((item) => item.status !== 'SYNCED');
    this.persistState();
  }
}