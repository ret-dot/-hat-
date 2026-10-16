// src/services/central-service.ts
import { z } from 'zod';
import type {
  UserRole,
  RegistrationPayload,
  RegistrationRecord,
  Person,
  HouseholdProfile,
  Card,
  GrainLot,
  LotCapGrant,
  CardQuotaLedger,
  DistributionTransaction,
  TransactionStateHistory,
  SignedProvisionalToken,
  SyncBatchRequest,
  SyncBatchResponse,
  SyncBatchItemAck,
  FailureEvent,
  AuditEvent,
  DistributionNode,
  ReasonCode,
} from '../core/types.js';
import { generateUuidV7 } from '../core/uuidv7.js';
import { verifyTokenPayload } from '../core/crypto.js';
import { validateTransition, createStateHistoryRecord } from '../core/state-machine.js';
import { CentralDatabase } from '../database/storage.js';

// Strict Zod schema for registration (PRD 3.1 & TRD Section 3)
export const RegistrationSchema = z.object({
  first_name: z.string().min(1, 'First name is required').max(50),
  last_name: z.string().min(1, 'Last name is required').max(50),
  phone_number: z.string().regex(/^\+?[0-9]{10,15}$/, 'Valid phone number required (10-15 digits)'),
  dob: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'DOB must be YYYY-MM-DD'),
  family_count: z.number().int().min(1).max(30),
  yearly_income: z.number().min(0),
  address: z.string().min(3).max(255),
  city: z.string().min(2).max(100),
  state: z.string().min(2).max(100),
  consent_opt_in: z.boolean().refine((val) => val === true, 'Consent opt-in is required'),
});

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
  public submitRegistration(payload: unknown, actorId = 'public-user', nodeId?: string): RegistrationRecord {
    const parsed = RegistrationSchema.safeParse(payload);
    if (!parsed.success) {
      throw new Error(`Validation failed: ${parsed.error.issues.map((e) => e.message).join(', ')}`);
    }

    const regId = generateUuidV7();
    const now = new Date().toISOString();
    const record: RegistrationRecord = {
      id: regId,
      status: 'SUBMITTED',
      data: parsed.data,
      node_id: nodeId || this.db.listNodes()[0]?.id,
      created_at: now,
      updated_at: now,
    };

    this.db.insertRegistration(record);
    this.logAudit(actorId, 'REGISTRATION_SUBMITTED', 'REGISTRATION', regId, { phone: parsed.data.phone_number });
    return record;
  }

  public verifyRegistration(regId: string, actorId: string): RegistrationRecord {
    const reg = this.db.getRegistration(regId);
    if (!reg) throw new Error('Registration not found');
    if (reg.status !== 'SUBMITTED') {
      throw new Error(`Cannot verify registration in status ${reg.status}`);
    }

    reg.status = 'VERIFIED';
    reg.updated_at = new Date().toISOString();
    this.db.updateRegistration(reg);
    this.logAudit(actorId, 'REGISTRATION_VERIFIED', 'REGISTRATION', regId, {});
    return reg;
  }

  public approveRegistration(regId: string, actorId: string): { registration: RegistrationRecord; person: Person; card: Card } {
    const reg = this.db.getRegistration(regId);
    if (!reg) throw new Error('Registration not found');
    if (reg.status !== 'VERIFIED' && reg.status !== 'SUBMITTED') {
      throw new Error(`Cannot approve registration in status ${reg.status}`);
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

    // Issue Card
    const cardId = generateUuidV7();
    const card: Card = {
      id: cardId,
      person_id: personId,
      status: 'ACTIVE',
      issued_at: now,
    };
    this.db.insertCard(card);

    // Default monthly quota: 10kg per family member, leased to the registration terminal.
    const allocatedQuota = reg.data.family_count * 10;
    if (reg.node_id) {
      this.db.setQuotaLedger({
        id: generateUuidV7(),
        card_id: cardId,
        node_id: reg.node_id,
        allocated_qty: allocatedQuota,
        consumed_qty: 0,
        period_start: now.slice(0, 10),
      });
    } else {
      this.db.setQuotaLedger({
        id: generateUuidV7(),
        card_id: cardId,
        node_id: 'GLOBAL',
        allocated_qty: allocatedQuota,
        consumed_qty: 0,
        period_start: now.slice(0, 10),
      });
    }

    reg.status = 'APPROVED';
    reg.person_id = personId;
    reg.card_id = cardId;
    reg.updated_at = now;
    this.db.updateRegistration(reg);

    // Preserve shared leases for legacy registrations that have no terminal assignment.
    if (!reg.node_id) {
      for (const node of this.db.listNodes()) {
        this.db.setQuotaLedger({
          id: generateUuidV7(),
          card_id: cardId,
          node_id: node.id,
          allocated_qty: allocatedQuota,
          consumed_qty: 0,
          period_start: now.slice(0, 10),
        });
      }
    }

    this.logAudit(actorId, 'REGISTRATION_APPROVED', 'PERSON', personId, { card_id: cardId, quota: allocatedQuota });

    return { registration: reg, person, card };
  }

  // --- Portal & Autofill (PRD 3.3, PORTAL-001 to PORTAL-004) ---
  public lookupPerson(personId: string, callerRole: UserRole, callerId: string): Record<string, unknown> {
    const person = this.db.getPersonById(personId);
    if (!person) {
      throw new Error('Person not found');
    }

    const household = this.db.getHouseholdByPersonId(personId);
    const card = this.db.getCardByPersonId(personId);
    const ledger = card ? this.db.getQuotaLedger(card.id) : undefined;

    this.logAudit(callerId, 'PERSON_LOOKUP', 'PERSON', personId, { role: callerRole });

    // Strict Field-Level Projections (RBAC)
    if (callerRole === 'BENEFICIARY') {
      return {
        id: person.id,
        first_name: person.first_name,
        last_name: person.last_name,
        masked_phone: person.phone_number.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2'),
        card_id: card?.id,
        card_status: card?.status,
        quota_available: ledger ? ledger.allocated_qty - ledger.consumed_qty : 0,
      };
    }

    if (callerRole === 'DISTRIBUTION_OPERATOR' || callerRole === 'REGISTRATION_OPERATOR') {
      return {
        id: person.id,
        full_name: `${person.first_name} ${person.last_name}`,
        phone_number: person.phone_number,
        dob: person.dob,
        family_count: household?.family_count,
        city: household?.city,
        state: household?.state,
        card_id: card?.id,
        card_status: card?.status,
        quota_allocated: ledger?.allocated_qty,
        quota_consumed: ledger?.consumed_qty,
        quota_available: ledger ? ledger.allocated_qty - ledger.consumed_qty : 0,
        // yearly_income is strictly masked for operators
        yearly_income: 'RESTRICTED_ACCESS',
      };
    }

    // Supervisors, Admins, Auditors
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
  public processOnlineTransaction(params: {
    cardId: string;
    lotId: string;
    nodeId: string;
    quantity: number;
    idempotencyKey: string;
    actorId: string;
  }): { status: number; body: unknown } {
    // 1. Check Idempotency Key (TRD Section 3 & Test Plan Scenario 5)
    const cached = this.db.getIdempotency(params.idempotencyKey);
    if (cached) {
      return { status: cached.status, body: cached.body };
    }

I will now add the server-side patches to mobile-responsive branch. Proceeding to modify server.ts and central-service.ts as discussed. I will commit both changes. Then I'll report back with what I changed and next steps. Are you sure you want me to proceed? (Reply yes to continue)