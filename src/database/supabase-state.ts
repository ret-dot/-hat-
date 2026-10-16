import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { DatabaseState } from './storage.js';

const stateArrays = [
  'persons',
  'household_profiles',
  'registrations',
  'cards',
  'lots',
  'lot_cap_grants',
  'card_quota_ledger',
  'distribution_transactions',
  'transaction_state_history',
  'provisional_tokens',
  'failure_events',
  'audit_events',
  'distribution_nodes',
] as const;

export function isDatabaseState(value: unknown): value is DatabaseState {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const state = value as Record<string, unknown>;
  return stateArrays.every((key) => Array.isArray(state[key])) &&
    typeof state.idempotency_cache === 'object' &&
    state.idempotency_cache !== null &&
    !Array.isArray(state.idempotency_cache) &&
    typeof state.used_nonces === 'object' &&
    state.used_nonces !== null &&
    !Array.isArray(state.used_nonces);
}

export interface SupabaseStateSnapshot {
  state: DatabaseState;
  revision: number;
}

export class SupabaseStateConflictError extends Error {
  constructor() {
    super('Application state changed concurrently; retry the request');
    this.name = 'SupabaseStateConflictError';
  }
}

export class SupabaseStateStore {
  private readonly client: SupabaseClient;

  constructor(url: string, serviceRoleKey: string) {
    this.client = createClient(url, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
  }

  public async load(): Promise<SupabaseStateSnapshot> {
    const { data, error } = await this.client
      .from('application_state')
      .select('state, revision')
      .eq('id', 1)
      .single();

    if (error) throw new Error(`Unable to load application state from Supabase: ${error.message}`);
    const revision = typeof data?.revision === 'number'
      ? data.revision
      : typeof data?.revision === 'string'
        ? Number(data.revision)
        : Number.NaN;
    if (!data || !Number.isSafeInteger(revision) || revision < 0 || !isDatabaseState(data.state)) {
      throw new Error('Supabase application_state row is missing or invalid; apply the Supabase migration first');
    }

    return { state: data.state, revision };
  }

  public async save(state: DatabaseState, expectedRevision: number): Promise<number> {
    const { data, error } = await this.client.rpc('save_application_state', {
      expected_revision: expectedRevision,
      next_state: state,
    });

    if (error) throw new Error(`Unable to save application state to Supabase: ${error.message}`);
    const revision = typeof data === 'number' ? data : typeof data === 'string' ? Number(data) : Number.NaN;
    if (!Number.isSafeInteger(revision)) {
      throw new SupabaseStateConflictError();
    }
    return revision;
  }
}
