import fs from 'node:fs';
import path from 'node:path';
import { SupabaseStateStore, isDatabaseState } from '../src/database/supabase-state.js';

const sourcePath = path.resolve(process.argv[2] || 'data/central_db.json');
const supabaseUrl = process.env.SUPABASE_URL;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !serviceRoleKey) {
  throw new Error('Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY before importing application state');
}

const parsed: unknown = JSON.parse(fs.readFileSync(sourcePath, 'utf8'));
if (!isDatabaseState(parsed)) {
  throw new Error(`The local database file does not match the expected application state schema: ${sourcePath}`);
}

const store = new SupabaseStateStore(supabaseUrl, serviceRoleKey);
const target = await store.load();
const isEmpty = Object.values(target.state).every((value) => {
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'object' && value !== null) return Object.keys(value).length === 0;
  return false;
});
if (target.revision !== 0 || !isEmpty) {
  throw new Error('Supabase already contains application state; import is allowed only into the untouched initial state');
}

await store.save(parsed, target.revision);
console.log(`Imported local application state from ${sourcePath}`);
