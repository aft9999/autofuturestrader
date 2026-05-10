import { createReadStream, existsSync, mkdirSync, unlinkSync, statSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { randomUUID } from 'node:crypto';
import multipart from '@fastify/multipart';
import { query } from '../lib/db.js';

const UPLOAD_DIR = '/root/aft-backend/uploads/releases';
if (!existsSync(UPLOAD_DIR)) mkdirSync(UPLOAD_DIR, { recursive: true });

function requireAdmin(req, reply) {
  const pwd = req.headers['x-admin-password'];
  if (!pwd || pwd !== process.env.ADMIN_PASSWORD) { reply.code(401).send({ error: 'Unauthorized' }); return false; }
  return true;
}

async function requireSubscriber(req, reply) {
  const auth = req.headers['authorization'];
  if (!auth?.startsWith('Bearer ')) { reply.code(401).send({ error: 'Unauthorized' }); return null; }
  try {
    const { verifyAccessToken } = await import('../lib/jwt.js');
    const payload = verifyAccessToken(auth.slice(7));
    const { rows } = await query(`SELECT status FROM subscriptions WHERE user_id = $1 AND status IN ('active','trialing') LIMIT 1`, [payload.sub]);
    if (!rows.length) { reply.code(403).send({ error: 'Active subscription required' }); return null; }
    return payload;
  } catch { reply.code(401).send({ error: 'Invalid token' }); return null; }
}

export default async function releaseRoutes(fastify) {
  await fastify.register(multipart, { limits: { fileSize: 100 * 1024 * 1024 } });

  fastify.get('/releases', async (req, reply) => {
    const isAdmin = req.headers['x-admin-password'] === process.env.ADMIN_PASSWORD;
    if (!isAdmin) { const user = await requireSubscriber(req, reply); if (!user) return; }
    const { rows } = await query(`SELECT id, original_name, description, version, file_size, uploaded_by, created_at FROM releases ORDER BY created_at DESC`);
    return reply.send({ releases: rows });
  });

  fastify.get('/releases/:id/download', async (req, reply) => {
    const isAdmin = req.headers['x-admin-password'] === process.env.ADMIN_PASSWORD;
    if (!isAdmin) { const user = await requireSubscriber(req, reply); if (!user) return; }
    const { rows } = await query('SELECT * FROM releases WHERE id = $1', [req.params.id]);
    if (!rows.length) return reply.code(404).send({ error: 'Release not found' });
    const filePath = join(UPLOAD_DIR, rows[0].filename);
    if (!existsSync(filePath)) return reply.code(404).send({ error: 'File not found' });
    const stat = statSync(filePath);
    reply.header('Content-Type', 'application/zip');
    reply.header('Content-Disposition', `attachment; filename="${rows[0].original_name}"`);
    reply.header('Content-Length', stat.size);
    return reply.send(createReadStream(filePath));
  });

  fastify.post('/releases', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    let fileBuffer = null, fileName = '', description = '', version = '';
    const parts = req.parts();
    for await (const part of parts) {
      if (part.type === 'file') { fileName = part.filename; const chunks = []; for await (const chunk of part.file) chunks.push(chunk); fileBuffer = Buffer.concat(chunks); }
      else if (part.fieldname === 'description') description = part.value || '';
      else if (part.fieldname === 'version') version = part.value || '';
    }
    if (!fileBuffer || !fileName) return reply.code(400).send({ error: 'No file uploaded' });
    if (extname(fileName).toLowerCase() !== '.zip') return reply.code(400).send({ error: 'Only .zip files allowed' });
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const storedFilename = `${timestamp}_${randomUUID()}.zip`;
    await writeFile(join(UPLOAD_DIR, storedFilename), fileBuffer);
    const { rows } = await query(
      `INSERT INTO releases (filename, original_name, description, version, file_size, uploaded_by) VALUES ($1,$2,$3,$4,$5,'admin') RETURNING *`,
      [storedFilename, fileName, description, version, fileBuffer.length]
    );
    return reply.code(201).send({ release: rows[0] });
  });

  fastify.put('/releases/:id', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { description, version } = req.body || {};
    const { rows } = await query(`UPDATE releases SET description=$1, version=$2 WHERE id=$3 RETURNING *`, [description||'', version||'', req.params.id]);
    if (!rows.length) return reply.code(404).send({ error: 'Not found' });
    return reply.send({ release: rows[0] });
  });

  fastify.delete('/releases/:id', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { rows } = await query('SELECT * FROM releases WHERE id = $1', [req.params.id]);
    if (!rows.length) return reply.code(404).send({ error: 'Not found' });
    const filePath = join(UPLOAD_DIR, rows[0].filename);
    if (existsSync(filePath)) try { unlinkSync(filePath); } catch {}
    await query('DELETE FROM releases WHERE id = $1', [req.params.id]);
    return reply.send({ ok: true });
  });
}
