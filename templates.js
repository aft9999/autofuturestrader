import { pipeline } from 'node:stream/promises';
import { createWriteStream, createReadStream, existsSync, mkdirSync, unlinkSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { query } from '../lib/db.js';

const UPLOAD_DIR = '/root/aft-backend/uploads/templates';

// Ensure upload directory exists
if (!existsSync(UPLOAD_DIR)) mkdirSync(UPLOAD_DIR, { recursive: true });

// ── Admin auth helper ─────────────────────────────────────────────────────────
function requireAdmin(req, reply) {
  const pwd = req.headers['x-admin-password'];
  if (!pwd || pwd !== process.env.ADMIN_PASSWORD) {
    reply.code(401).send({ error: 'Unauthorized' });
    return false;
  }
  return true;
}

// ── JWT auth helper ───────────────────────────────────────────────────────────
async function requireSubscriber(req, reply) {
  const auth = req.headers['authorization'];
  if (!auth?.startsWith('Bearer ')) {
    reply.code(401).send({ error: 'Unauthorized' });
    return null;
  }
  try {
    const { verifyAccessToken } = await import('../lib/jwt.js');
    const token = auth.slice(7);
    const payload = verifyAccessToken(token);

    // Check active or trialing subscription
    const { rows } = await query(
      `SELECT status FROM subscriptions WHERE user_id = $1 AND status IN ('active','trialing') LIMIT 1`,
      [payload.sub]
    );
    if (!rows.length) {
      reply.code(403).send({ error: 'Active subscription required' });
      return null;
    }
    return payload;
  } catch {
    reply.code(401).send({ error: 'Invalid token' });
    return null;
  }
}

// ── Parse multipart body manually ─────────────────────────────────────────────
async function parseMultipart(req) {
  return new Promise((resolve, reject) => {
    const contentType = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=([^\s;]+)/);
    if (!boundaryMatch) return reject(new Error('No boundary found'));

    const boundary = '--' + boundaryMatch[1];
    const chunks = [];

    req.raw.on('data', chunk => chunks.push(chunk));
    req.raw.on('end', () => {
      const body = Buffer.concat(chunks);
      const bodyStr = body.toString('binary');
      const parts = bodyStr.split(boundary).slice(1, -1);

      const fields = {};
      let fileBuffer = null;
      let fileName = '';
      let fileExt = '';

      for (const part of parts) {
        const [headerSection, ...contentParts] = part.split('\r\n\r\n');
        const content = contentParts.join('\r\n\r\n').replace(/\r\n$/, '');

        const nameMatch = headerSection.match(/name="([^"]+)"/);
        const filenameMatch = headerSection.match(/filename="([^"]+)"/);

        if (!nameMatch) continue;
        const fieldName = nameMatch[1];

        if (filenameMatch) {
          fileName = filenameMatch[1];
          fileExt = extname(fileName).toLowerCase();
          fileBuffer = Buffer.from(content, 'binary');
        } else {
          fields[fieldName] = content.trim();
        }
      }

      resolve({ fields, fileBuffer, fileName, fileExt });
    });
    req.raw.on('error', reject);
  });
}

export default async function templateRoutes(fastify) {

  // ── GET /templates — list all (subscribers only) ──────────────────────────
  fastify.get('/templates', async (req, reply) => {
    const user = await requireSubscriber(req, reply);
    if (!user) return;

    const { rows } = await query(
      `SELECT id, original_name, description, file_size, uploaded_by, created_at
       FROM templates ORDER BY created_at DESC`
    );
    return reply.send({ templates: rows });
  });

  // ── GET /templates/:id/download — download file (subscribers only) ─────────
  fastify.get('/templates/:id/download', async (req, reply) => {
    const user = await requireSubscriber(req, reply);
    if (!user) return;

    const { rows } = await query(
      'SELECT * FROM templates WHERE id = $1', [req.params.id]
    );
    if (!rows.length) return reply.code(404).send({ error: 'Template not found' });

    const template = rows[0];
    const filePath = join(UPLOAD_DIR, template.filename);

    if (!existsSync(filePath)) {
      return reply.code(404).send({ error: 'File not found on server' });
    }

    // Stream the file exactly as stored — no parsing or encoding
    const stat = statSync(filePath);
    reply.header('Content-Type', 'application/xml');
    reply.header('Content-Disposition', `attachment; filename="${template.original_name}"`);
    reply.header('Content-Length', stat.size);

    const stream = createReadStream(filePath);
    return reply.send(stream);
  });

  // ── POST /templates — upload (admin only) ─────────────────────────────────
  fastify.post('/templates', { config: { rawBody: false } }, async (req, reply) => {
    if (!requireAdmin(req, reply)) return;

    let parsed;
    try {
      parsed = await parseMultipart(req);
    } catch (err) {
      return reply.code(400).send({ error: 'Invalid multipart data: ' + err.message });
    }

    const { fields, fileBuffer, fileName, fileExt } = parsed;

    if (!fileBuffer || !fileName) {
      return reply.code(400).send({ error: 'No file uploaded' });
    }
    if (fileExt !== '.xml') {
      return reply.code(400).send({ error: 'Only .xml files are allowed' });
    }

    // Save with UUID + timestamp to preserve uniqueness
    const now = new Date();
    const timestamp = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const storedFilename = `${timestamp}_${randomUUID()}${fileExt}`;
    const filePath = join(UPLOAD_DIR, storedFilename);

    // Write raw binary — no transformation
    const { writeFile } = await import('node:fs/promises');
    await writeFile(filePath, fileBuffer);

    const fileSize = fileBuffer.length;
    const description = fields.description || '';

    const { rows } = await query(
      `INSERT INTO templates (filename, original_name, description, file_size, uploaded_by)
       VALUES ($1, $2, $3, $4, 'admin') RETURNING *`,
      [storedFilename, fileName, description, fileSize]
    );

    return reply.code(201).send({ template: rows[0] });
  });

  // ── DELETE /templates/:id — delete (admin only) ───────────────────────────
  fastify.delete('/templates/:id', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;

    const { rows } = await query(
      'SELECT * FROM templates WHERE id = $1', [req.params.id]
    );
    if (!rows.length) return reply.code(404).send({ error: 'Template not found' });

    const template = rows[0];
    const filePath = join(UPLOAD_DIR, template.filename);

    // Delete file from disk
    if (existsSync(filePath)) {
      try { unlinkSync(filePath); } catch {}
    }

    // Delete from DB
    await query('DELETE FROM templates WHERE id = $1', [req.params.id]);
    return reply.send({ ok: true });
  });
}
