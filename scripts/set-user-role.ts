import { createClient } from '@supabase/supabase-js';

const roles = new Set<string>([
  'BENEFICIARY',
  'REGISTRATION_OPERATOR',
  'DISTRIBUTION_OPERATOR',
  'SUPERVISOR',
  'ADMINISTRATOR',
  'RECONCILIATION_OFFICER',
  'AUDITOR',
  'SECURITY_TESTER',
  'SYSTEM_OPERATOR',
]);

const [userId, requestedRole] = process.argv.slice(2);
const supabaseUrl = process.env.SUPABASE_URL;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!userId || !requestedRole || !roles.has(requestedRole)) {
  throw new Error(`Usage: npx tsx scripts/set-user-role.ts <user-id> <${[...roles].join('|')}>`);
}
if (!supabaseUrl || !serviceRoleKey) {
  throw new Error('Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY before assigning a role');
}

const supabase = createClient(supabaseUrl, serviceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});
const { data, error } = await supabase.auth.admin.getUserById(userId);
if (error) throw new Error(`Unable to load Supabase user: ${error.message}`);
if (!data.user) throw new Error('Supabase user was not found');

const { error: updateError } = await supabase.auth.admin.updateUserById(userId, {
  app_metadata: { ...data.user.app_metadata, role: requestedRole },
});
if (updateError) throw new Error(`Unable to assign user role: ${updateError.message}`);

console.log(`Assigned ${requestedRole} role to Supabase user ${userId}`);
