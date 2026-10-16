# Supabase and Vercel setup

## 1. Create the Supabase project

From the Supabase project settings, collect the project URL, publishable/anon key, and service-role key. Keep the service-role key private.

Apply [`../supabase/migrations/20261016000000_application_state.sql`](../supabase/migrations/20261016000000_application_state.sql) in the Supabase SQL editor or through the Supabase CLI. The application stores its existing database state in one JSONB row and uses a revision check to reject concurrent writes rather than lose updates. This preserves the current synchronous service layer; it is intended for this app's initial deployment and modest traffic, not as a normalized high-throughput schema.

## 2. Configure Vercel environment variables

Add these variables for the Vercel project:

| Variable | Scope | Value |
| --- | --- | --- |
| `VITE_SUPABASE_URL` | Frontend (public) | Supabase project URL |
| `VITE_SUPABASE_PUBLISHABLE_KEY` | Frontend (public) | Supabase publishable key |
| `SUPABASE_URL` | Server only | Same Supabase project URL |
| `SUPABASE_ANON_KEY` | Server only | Supabase anon key (the publishable key also works) |
| `SUPABASE_SERVICE_ROLE_KEY` | Server only | Supabase service-role key |

Never prefix the service-role key with `VITE_`; Vite embeds `VITE_` values in browser assets. Do not configure `AUTH_TOKEN_SECRET` for this Supabase-auth deployment.

Redeploy after setting the variables. `api/[...path].ts` exposes the Express API as a Vercel function; keep the Vite build command as `npm run build` and output directory as `dist`.

## 3. Create users and assign roles

Create accounts through Supabase Auth (disable public sign-ups if accounts should be invitation-only). The API requires a trusted `app_metadata.role`, so public/user-editable metadata cannot grant privileges.

Run the role assignment command from a trusted machine with the server-only service key set:

```powershell
$env:SUPABASE_URL = "https://YOUR_PROJECT.supabase.co"
$env:SUPABASE_SERVICE_ROLE_KEY = "YOUR_SERVER_ONLY_SERVICE_ROLE_KEY"
npx tsx scripts/set-user-role.ts USER_UUID ADMINISTRATOR
```

Use the least-privileged role needed. Users sign into the deployed app with their Supabase email and password. The local demo-admin button is used only when Supabase is not configured and the server is not in production.

## 4. Data and runtime limitations

The database starts with the demo seed data when its state is empty. Existing `data/central_db.json` records are not uploaded automatically.

To migrate the local JSON database before the first API request seeds the production database, run this from the repository on a trusted machine:

```powershell
$env:SUPABASE_URL = "https://YOUR_PROJECT.supabase.co"
$env:SUPABASE_SERVICE_ROLE_KEY = "YOUR_SERVER_ONLY_SERVICE_ROLE_KEY"
npx tsx scripts/import-local-state.ts
```

The importer refuses to overwrite a non-empty Supabase state. Treat the source file and service-role key as sensitive, and never include either in a client bundle or public repository.

Vercel functions are stateless. Online API reads/writes persist through Supabase, but the current edge-node offline outbox and signing keys still depend on local files/in-memory state and are not durable across Vercel function instances. Do not rely on offline issuance in production on Vercel until edge state and private-key lifecycle are moved to durable, node-specific storage.
