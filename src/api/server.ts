// src/api/server.ts
import express, { Request, RequestHandler } from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { CentralDatabase } from '../database/storage.js';
import { CentralService } from '../services/central-service.js';
import { EdgeDistributionNode } from '../edge-node/edge-node.js';
import { generateNodeKeyPair } from '../core/crypto.js';
import { generateUuidV7 } from '../core/uuidv7.js';
import type { SyncBatchRequest } from '../core/types.js';
import { createAuthMiddleware, createLocalDemoLogin, requireRoles } from './auth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createServer(customDb?: CentralDatabase, authSecret = process.env.AUTH_TOKEN_SECRET) {
  const app = express();
  app.use(cors());
  app.use(express.json());
  const localDemoAuth = !authSecret && process.env.NODE_ENV !== 'production';
  const effectiveAuthSecret = authSecret || (localDemoAuth ? randomBytes(32).toString('base64url') : undefined);

  const dbPath = path.join(__dirname, '../../data/central_db.json');
  const db = customDb || new CentralDatabase(dbPath);
  const service = new CentralService(db);

  // In-memory registry of EdgeNode instances for interactive demo
  const edgeNodes = new Map<string, EdgeDistributionNode>();
  // Ensure default seed data exists
  async function seedDefaults() {
    if (db.listNodes().length === 0) {
      const keysA = await generateNodeKeyPair();
      const nodeAId = 'node-alpha-001';
      db.insertNode({
        id: nodeAId,
        name: 'Distribution Node Alpha (District 1)',
        public_key: keysA.publicKeyHex,
        status: 'ONLINE',
        last_heartbeat: new Date().toISOString(),
        outbox_depth: 0,
        location: 'Sector 4 Community Depot',
      });

      const edgeA = new EdgeDistributionNode({
        nodeId: nodeAId,
        nodeName: 'Distribution Node Alpha',
        privateKeyHex: keysA.privateKeyHex,
        publicKeyHex: keysA.publicKeyHex,
        dataDir: path.join(__dirname, '../../data/nodes'),
      });
      edgeNodes.set(nodeAId, edgeA);

      const keysB = await generateNodeKeyPair();
      const nodeBId = 'node-beta-002';
      db.insertNode({
        id: nodeBId,
        name: 'Distribution Node Beta (Rural Outpost)',
        public_key: keysB.publicKeyHex,
        status: 'ONLINE',
        last_heartbeat: new Date().toISOString(),
        outbox_depth: 0,
        location: 'Rural Outpost Station 9',
      });

      const edgeB = new EdgeDistributionNode({
        nodeId: nodeBId,
        nodeName: 'Distribution Node Beta',
        privateKeyHex: keysB.privateKeyHex,
        publicKeyHex: keysB.publicKeyHex,
        dataDir: path.join(__dirname, '../../data/nodes'),
      });
      edgeNodes.set(nodeBId, edgeB);
    } else {
      // Re-hydrate edge nodes
      for (const n of db.listNodes()) {
        if (!edgeNodes.has(n.id)) {
          const keys = await generateNodeKeyPair();
          const edge = new EdgeDistributionNode({
            nodeId: n.id,
            nodeName: n.name,
            privateKeyHex: keys.privateKeyHex,
            publicKeyHex: n.public_key || keys.publicKeyHex,
            dataDir: path.join(__dirname, '../../data/nodes'),
          });
          edgeNodes.set(n.id, edge);
        }
      }
    }

    if (db.listLots().length === 0) {
      const lot1Id = 'lot-wheat-2026-01';
      db.insertLot({
        id: lot1Id,
        name: 'National Reserve Wheat Batch 2026-A',
        grain_type: 'Wheat',
        total_quantity: 5000,
        remaining_quantity: 4850,
      });

      const lot2Id = 'lot-rice-2026-02';
      db.insertLot({
        id: lot2Id,
        name: 'Basmati Emergency Stockpile',
        grain_type: 'Rice',
        total_quantity: 3000,
        remaining_quantity: 2950,
      });

      // Seed grants
      const nodes = db.listNodes();
      for (const n of nodes) {
        db.insertLotGrant({
          id: generateUuidV7(),
          lot_id: lot1Id,
          node_id: n.id,
          max_quantity: 500,
          remaining_quantity: 500,
          expires_at: Math.floor(Date.now() / 1000) + 86400 * 7,
          signature: 'sig_grant_valid',
        });
        const edge = edgeNodes.get(n.id);
        if (edge) {
          edge.setGrant(lot1Id, 500, Math.floor(Date.now() / 1000) + 86400 * 7);
        }
      }
    }
  }

  seedDefaults().catch((error: unknown) => {
    console.error('Unable to seed local demo data:', error);
  });

  // --- API Routes ---

  // Health
  app.get('/api/health', (req, res) => {
    res.json({ status: 'UP', timestamp: new Date().toISOString() });
  });

  app.get('/', (_req, res) => {
    res.json({ status: 'UP', message: 'API server running. Start the website with npm run dev.' });
  });

  if (localDemoAuth && effectiveAuthSecret) {
    app.post('/api/v1/auth/demo', createLocalDemoLogin(effectiveAuthSecret));
  }

  // 1. Registrations (PRD 3.1 & TRD Section 2)
  app.post('/api/v1/registrations', (req, res) => {
    try {
      const record = service.submitRegistration(req.body, 'public-registration');
      res.status(201).json({ id: record.id, status: record.status, created_at: record.created_at });
    } catch (e: any) {
      res.status(400).json({ code: 'ERR_101', message: e.message });
    }
  });

  app.use('/api/v1', createAuthMiddleware(effectiveAuthSecret));

  app.get('/api/v1/registrations', requireRoles('REGISTRATION_OPERATOR', 'SUPERVISOR', 'ADMINISTRATOR', 'AUDITOR'), (req, res) => {
    res.json(db.listRegistrations());
  });

  app.post('/api/v1/registrations/:id/verify', requireRoles('REGISTRATION_OPERATOR', 'SUPERVISOR', 'ADMINISTRATOR'), (req: Request<{ id: string }>, res) => {
    try {
      const actor = req.auth!.sub;
      const record = service.verifyRegistration(req.params.id, actor);
      res.json(record);
    } catch (e: any) {
      res.status(400).json({ code: 'ERR_401', message: e.message });
    }
  });

  app.post('/api/v1/registrations/:id/approve', requireRoles('SUPERVISOR', 'ADMINISTRATOR'), (req: Request<{ id: string }>, res) => {
    try {
      const actor = req.auth!.sub;
      const result = service.approveRegistration(req.params.id, actor);
      // Also update in-memory edgeNodes map so offline mode immediately has local lease:
      const allocatedQuota = result.registration.data.family_count * 10;
      for (const edge of edgeNodes.values()) {
        edge.allocateLocalLease(result.card.id, allocatedQuota);
      }
      res.status(200).json(result);
    } catch (e: any) {
      res.status(400).json({ code: 'ERR_401', message: e.message });
    }
  });

  app.get('/api/v1/cards', requireRoles('DISTRIBUTION_OPERATOR', 'SUPERVISOR', 'ADMINISTRATOR'), (req, res) => {
    const cards = db.listCards().map((c) => {
      const person = db.getPersonById(c.person_id);
      const household = db.getHouseholdByPersonId(c.person_id);
      const ledger = db.getQuotaLedger(c.id);
      return {
        id: c.id,
        person_id: c.person_id,
        status: c.status,
        issued_at: c.issued_at,
        first_name: person?.first_name || '',
        last_name: person?.last_name || '',
        full_name: person ? `${person.first_name} ${person.last_name}` : 'Unknown',
        phone_number: person?.phone_number || '',
        family_count: household?.family_count || 1,
        address: household?.address || '',
        city: household?.city || '',
        state: household?.state || '',
        allocated_qty: ledger?.allocated_qty || 0,
        consumed_qty: ledger?.consumed_qty || 0,
        remaining_qty: ledger ? Math.max(0, ledger.allocated_qty - ledger.consumed_qty) : 0,
      };
    });
    res.json(cards);
  });

  // 2. Beneficiary Lookup & Autofill (PRD 3.3, TRD Section 2)
  app.get('/api/v1/persons/:id', requireRoles('BENEFICIARY', 'REGISTRATION_OPERATOR', 'DISTRIBUTION_OPERATOR', 'SUPERVISOR', 'ADMINISTRATOR', 'AUDITOR'), (req: Request<{ id: string }>, res) => {
    try {
      const { role } = req.auth!;
      if (role === 'BENEFICIARY' && req.params.id !== req.auth!.sub) {
        return res.status(403).json({ code: 'ERR_FORBIDDEN', message: 'Beneficiaries may only access their own record' });
      }
      const actor = req.auth!.sub;
      const data = service.lookupPerson(req.params.id, role, actor);
      res.json(data);
    } catch (e: any) {
      res.status(404).json({ code: 'ERR_404', message: e.message });
    }
  });

  app.post('/api/v1/persons/:id/autofill', requireRoles('BENEFICIARY', 'REGISTRATION_OPERATOR', 'DISTRIBUTION_OPERATOR', 'SUPERVISOR', 'ADMINISTRATOR', 'AUDITOR'), (req: Request<{ id: string }>, res) => {
    try {
      const { role } = req.auth!;
      if (role === 'BENEFICIARY' && req.params.id !== req.auth!.sub) {
        return res.status(403).json({ code: 'ERR_FORBIDDEN', message: 'Beneficiaries may only access their own record' });
      }
      const actor = req.auth!.sub;
      const template = req.body.template || 'DISTRIBUTION_RECEIPT';
      const doc = service.autofillTemplate(req.params.id, template, role, actor);
      res.json(doc);
    } catch (e: any) {
      res.status(404).json({ code: 'ERR_404', message: e.message });
    }
  });

  // 3. Transactions (TRD Section 1 & api-spec.yaml)
  app.post('/api/v1/transactions', requireRoles('DISTRIBUTION_OPERATOR', 'SUPERVISOR', 'ADMINISTRATOR'), (req, res) => {
    const idempotencyKey = req.headers['idempotency-key'] as string;
    if (!idempotencyKey) {
      return res.status(400).json({
        code: 'ERR_101',
        message: "Missing mandatory 'Idempotency-Key' header",
        retryable: false,
      });
    }

    const { card_id, lot_id, node_id, quantity } = req.body;
    if (!card_id || !lot_id || !quantity) {
      return res.status(400).json({ code: 'ERR_101', message: 'Missing required transaction fields' });
    }

    const actor = req.auth!.sub;
    const result = service.processOnlineTransaction({
      cardId: card_id,
      lotId: lot_id,
      nodeId: node_id || db.listNodes()[0]?.id || 'node-default',
      quantity: Number(quantity),
      idempotencyKey,
      actorId: actor,
    });

    res.status(result.status).json(result.body);
  });

  app.get('/api/v1/transactions', requireRoles('RECONCILIATION_OFFICER', 'SUPERVISOR', 'ADMINISTRATOR', 'AUDITOR'), (req, res) => {
    res.json(db.listTransactions());
  });

  app.get('/api/v1/transactions/:id/history', requireRoles('RECONCILIATION_OFFICER', 'SUPERVISOR', 'ADMINISTRATOR', 'AUDITOR'), (req: Request<{ id: string }>, res) => {
    res.json(db.getStateHistory(req.params.id));
  });

  // 4. Batch Sync (api-spec.yaml, reconciliation.md)
  app.post('/api/v1/nodes/:id/sync', requireRoles('SYSTEM_OPERATOR', 'RECONCILIATION_OFFICER', 'ADMINISTRATOR'), async (req: Request<{ id: string }>, res) => {
    try {
      const result = await service.reconcileBatch(req.params.id, req.body as SyncBatchRequest);
      res.status(200).json(result);
    } catch (e: any) {
      res.status(400).json({ code: 'ERR_401', message: e.message });
    }
  });

  // 5. Edge Node Local Operations
  app.get('/api/v1/edge-nodes/:id/status', requireRoles('DISTRIBUTION_OPERATOR', 'SUPERVISOR', 'ADMINISTRATOR', 'SYSTEM_OPERATOR'), (req: Request<{ id: string }>, res) => {
    const edge = edgeNodes.get(req.params.id);
    if (!edge) return res.status(404).json({ message: 'Edge node not found' });
    res.json({
      nodeId: edge.config.nodeId,
      counter: edge.getCounter(),
      outboxDepth: edge.getOutboxDepth(),
      isOnline: edge.isOnline,
    });
  });

  app.post('/api/v1/edge-nodes/:id/issue', requireRoles('DISTRIBUTION_OPERATOR', 'SUPERVISOR', 'ADMINISTRATOR'), async (req: Request<{ id: string }>, res) => {
    const edge = edgeNodes.get(req.params.id);
    if (!edge) return res.status(404).json({ message: 'Edge node not found' });
    try {
      const { card_id, lot_id, grant_id, quantity, allow_fallback } = req.body;
      const result = await edge.issueProvisionalGrain({
        cardId: card_id,
        lotId: lot_id,
        grantId: grant_id || lot_id,
        quantity: Number(quantity),
        idempotencyKey: (req.headers['idempotency-key'] as string) || generateUuidV7(),
        allowFallback: allow_fallback === true && ['SUPERVISOR', 'ADMINISTRATOR'].includes(req.auth!.role),
      });

      // Update central node outbox tracking
      const centralNode = db.getNode(req.params.id);
      if (centralNode) {
        centralNode.outbox_depth = edge.getOutboxDepth();
        db.updateNode(centralNode);
      }

      res.status(200).json(result);
    } catch (e: any) {
      res.status(409).json({ code: 'ERR_409', message: e.message });
    }
  });

  app.post('/api/v1/edge-nodes/:id/sync-now', requireRoles('SYSTEM_OPERATOR', 'RECONCILIATION_OFFICER', 'ADMINISTRATOR'), async (req: Request<{ id: string }>, res) => {
    const edge = edgeNodes.get(req.params.id);
    if (!edge) return res.status(404).json({ message: 'Edge node not found' });

    const batch = edge.generateSyncBatch();
    if (!batch) {
      return res.json({ message: 'Outbox empty, nothing to sync', synced: 0 });
    }

    try {
      const syncResponse = await service.reconcileBatch(req.params.id, batch);
      edge.processSyncResponse(syncResponse);

      const centralNode = db.getNode(req.params.id);
      if (centralNode) {
        centralNode.outbox_depth = edge.getOutboxDepth();
        db.updateNode(centralNode);
      }

      res.json(syncResponse);
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  app.post('/api/v1/edge-nodes/:id/toggle-online', requireRoles('SYSTEM_OPERATOR', 'ADMINISTRATOR'), (req: Request<{ id: string }>, res) => {
    const edge = edgeNodes.get(req.params.id);
    if (!edge) return res.status(404).json({ message: 'Edge node not found' });
    edge.isOnline = !edge.isOnline;

    const centralNode = db.getNode(req.params.id);
    if (centralNode) {
      centralNode.status = edge.isOnline ? 'ONLINE' : 'OFFLINE';
      db.updateNode(centralNode);
    }

    res.json({ isOnline: edge.isOnline });
  });

  // 6. Quotas & Admin (TRD Section 2)
  app.get('/api/v1/admin/quotas', requireRoles('SUPERVISOR', 'ADMINISTRATOR'), (req, res) => {
    res.json({
      lots: db.listLots(),
      grants: db.listGrants(),
      quotas: db.listQuotaLedger(),
      cards: db.listCards(),
    });
  });

  app.post('/api/v1/admin/leases', requireRoles('SUPERVISOR', 'ADMINISTRATOR'), (req, res) => {
    const { card_id, node_id, quantity } = req.body;
    db.setQuotaLedger({
      id: generateUuidV7(),
      card_id,
      node_id,
      allocated_qty: Number(quantity),
      consumed_qty: 0,
      period_start: new Date().toISOString().slice(0, 10),
    });

    const edge = edgeNodes.get(node_id);
    if (edge) {
      edge.allocateLocalLease(card_id, Number(quantity));
    }

    res.json({ success: true, message: 'Quota lease allocated successfully' });
  });

  app.get('/api/v1/nodes', requireRoles('DISTRIBUTION_OPERATOR', 'SUPERVISOR', 'ADMINISTRATOR', 'SYSTEM_OPERATOR', 'AUDITOR'), (req, res) => {
    res.json(db.listNodes());
  });

  app.get('/api/v1/lots', requireRoles('DISTRIBUTION_OPERATOR', 'SUPERVISOR', 'ADMINISTRATOR'), (req, res) => {
    res.json(db.listLots());
  });

  app.post('/api/v1/lots', requireRoles('ADMINISTRATOR'), (req, res) => {
    const { name, grain_type, total_quantity } = req.body;
    const lotId = `lot-${Date.now()}`;
    const lot = {
      id: lotId,
      name,
      grain_type,
      total_quantity: Number(total_quantity),
      remaining_quantity: Number(total_quantity),
    };
    db.insertLot(lot);
    res.status(201).json(lot);
  });

  // 7. Metrics & Analytics (failure-catalog.md)
  app.get('/api/v1/metrics', requireRoles('ADMINISTRATOR', 'AUDITOR'), (req, res) => {
    res.json(service.getMetrics());
  });

  // 8. Immutable Audit Log (PRD 4 & database.md)
  app.get('/api/v1/audit', requireRoles('ADMINISTRATOR', 'AUDITOR'), (req, res) => {
    res.json(db.listAuditEvents());
  });

  // 9. Clear Full Database and Reset State (Admin reset)
  app.post('/api/v1/admin/reset', requireRoles('ADMINISTRATOR'), async (req, res) => {
    try {
      db.clearAllData();
      const nodeDir = path.join(__dirname, '../../data/nodes');
      if (fs.existsSync(nodeDir)) {
        const files = fs.readdirSync(nodeDir);
        for (const file of files) {
          try {
            fs.unlinkSync(path.join(nodeDir, file));
          } catch {}
        }
      }
      edgeNodes.clear();
      await seedDefaults();
      res.json({ success: true, message: 'All database records and stored state cleared successfully' });
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  return { app, service, db, edgeNodes };
}

// If executed directly, run standalone API server
if (process.argv[1]?.endsWith('server.ts') || process.argv[1]?.endsWith('server.js')) {
  const PORT = Number.parseInt(process.env.PORT || '3001', 10);
  const { app } = createServer();
  const localDemoAuth = !process.env.AUTH_TOKEN_SECRET && process.env.NODE_ENV !== 'production';
  const host = localDemoAuth ? '127.0.0.1' : undefined;
  const onListening = () => {
    console.log(`Grain Distribution API running on http://localhost:${PORT}`);
    if (host) console.warn('Local demo authentication enabled: administrator access is restricted to localhost.');
  };
  if (host) app.listen(PORT, host, onListening);
  else app.listen(PORT, onListening);
}
