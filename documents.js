import { createReadStream, existsSync, mkdirSync, unlinkSync, statSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { randomUUID } from 'node:crypto';
import multipart from '@fastify/multipart';
import { query } from '../lib/db.js';

const UPLOAD_DIR = '/root/aft-backend/uploads/documents';
const ALLOWED_TYPES = ['.pdf', '.doc', '.docx', '.mp4', '.mov', '.avi', '.mkv', '.webm', '.jpg', '.jpeg', '.png', '.gif', '.zip'];
const VIDEO_TYPES = ['.mp4', '.mov', '.avi', '.mkv', '.webm'];
const IMAGE_TYPES = ['.jpg', '.jpeg', '.png', '.gif'];

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

export default async function documentRoutes(fastify) {
  try {
    await fastify.register(multipart, { limits: { fileSize: 500 * 1024 * 1024 } }); // 500MB for videos
  } catch (e) {
    if (!e.message.includes('already registered')) throw e;
  }

  fastify.get('/documents', async (req, reply) => {
    const isAdmin = req.headers['x-admin-password'] === process.env.ADMIN_PASSWORD;
    if (!isAdmin) { const user = await requireSubscriber(req, reply); if (!user) return; }
    const { rows } = await query(`SELECT id, original_name, title, description, file_type, file_size, uploaded_by, created_at FROM documents ORDER BY created_at DESC`);
    return reply.send({ documents: rows });
  });

  fastify.get('/documents/:id/download', async (req, reply) => {
    const isAdmin = req.headers['x-admin-password'] === process.env.ADMIN_PASSWORD;
    if (!isAdmin) { const user = await requireSubscriber(req, reply); if (!user) return; }
    const { rows } = await query('SELECT * FROM documents WHERE id = $1', [req.params.id]);
    if (!rows.length) return reply.code(404).send({ error: 'Not found' });
    const filePath = join(UPLOAD_DIR, rows[0].filename);
    if (!existsSync(filePath)) return reply.code(404).send({ error: 'File not found' });
    const stat = statSync(filePath);
    const ext = rows[0].file_type;
    const mimeTypes = {
      '.pdf': 'application/pdf', '.doc': 'application/msword',
      '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      '.mp4': 'video/mp4', '.mov': 'video/quicktime', '.avi': 'video/x-msvideo',
      '.mkv': 'video/x-matroska', '.webm': 'video/webm',
      '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif',
      '.zip': 'application/zip'
    };
    reply.header('Content-Type', mimeTypes[ext] || 'application/octet-stream');
    reply.header('Content-Disposition', `attachment; filename="${rows[0].original_name}"`);
    reply.header('Content-Length', stat.size);
    return reply.send(createReadStream(filePath));
  });

  // Stream for in-browser viewing (no download header)
  fastify.get('/documents/:id/view', async (req, reply) => {
    const isAdmin = req.headers['x-admin-password'] === process.env.ADMIN_PASSWORD;
    if (!isAdmin) { const user = await requireSubscriber(req, reply); if (!user) return; }
    const { rows } = await query('SELECT * FROM documents WHERE id = $1', [req.params.id]);
    if (!rows.length) return reply.code(404).send({ error: 'Not found' });
    const filePath = join(UPLOAD_DIR, rows[0].filename);
    if (!existsSync(filePath)) return reply.code(404).send({ error: 'File not found' });
    const stat = statSync(filePath);
    const ext = rows[0].file_type;
    const mimeTypes = {
      '.pdf': 'application/pdf', '.mp4': 'video/mp4', '.mov': 'video/quicktime',
      '.webm': 'video/webm', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
      '.png': 'image/png', '.gif': 'image/gif'
    };
    reply.header('Content-Type', mimeTypes[ext] || 'application/octet-stream');
    reply.header('Content-Length', stat.size);
    reply.header('Cache-Control', 'no-store');
    return reply.send(createReadStream(filePath));
  });

  fastify.post('/documents', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    let fileBuffer = null, fileName = '', description = '', title = '';
    const parts = req.parts();
    for await (const part of parts) {
      if (part.type === 'file') {
        fileName = part.filename;
        const chunks = [];
        for await (const chunk of part.file) chunks.push(chunk);
        fileBuffer = Buffer.concat(chunks);
      } else if (part.fieldname === 'description') description = part.value || '';
      else if (part.fieldname === 'title') title = part.value || '';
    }
    if (!fileBuffer || !fileName) return reply.code(400).send({ error: 'No file uploaded' });
    const fileExt = extname(fileName).toLowerCase();
    if (!ALLOWED_TYPES.includes(fileExt)) return reply.code(400).send({ error: `File type not allowed. Allowed: ${ALLOWED_TYPES.join(', ')}` });
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const storedFilename = `${timestamp}_${randomUUID()}${fileExt}`;
    await writeFile(join(UPLOAD_DIR, storedFilename), fileBuffer);
    const { rows } = await query(
      `INSERT INTO documents (filename, original_name, title, description, file_type, file_size, uploaded_by) VALUES ($1,$2,$3,$4,$5,$6,'admin') RETURNING *`,
      [storedFilename, fileName, title || fileName, description, fileExt, fileBuffer.length]
    );
    return reply.code(201).send({ document: rows[0] });
  });

  fastify.put('/documents/:id', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { title, description } = req.body || {};
    const { rows } = await query(`UPDATE documents SET title=$1, description=$2 WHERE id=$3 RETURNING *`, [title||'', description||'', req.params.id]);
    if (!rows.length) return reply.code(404).send({ error: 'Not found' });
    return reply.send({ document: rows[0] });
  });

  fastify.delete('/documents/:id', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { rows } = await query('SELECT * FROM documents WHERE id = $1', [req.params.id]);
    if (!rows.length) return reply.code(404).send({ error: 'Not found' });
    const filePath = join(UPLOAD_DIR, rows[0].filename);
    if (existsSync(filePath)) try { unlinkSync(filePath); } catch {}
    await query('DELETE FROM documents WHERE id = $1', [req.params.id]);
    return reply.send({ ok: true });
  });
}
