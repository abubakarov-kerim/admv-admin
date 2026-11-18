import http from 'node:http';
import {Readable} from 'node:stream';
import {randomBytes, pbkdf2Sync, createHash} from 'node:crypto';
import handler from './handler.mjs';

// One owner, one process: bounded in-memory counter, no IP/user database.
let windowEnd = 0, attempts = 0;
const env = {...process.env, LOGIN_LIMITER: {async limit() {
  const now = Date.now();
  if (now >= windowEnd) { windowEnd = now + 60000; attempts = 0; }
  return {success: ++attempts <= 6};
}}};
// Render accepts a password as an encrypted server-side secret. Convert it to a
// salted hash on startup; never send it to the website or write it to logs.
if (env.ADMV_PASSWORD) {
  if (env.ADMV_PASSWORD.length < 10 || env.ADMV_PASSWORD.length > 256) { console.error('Пароль должен содержать от 10 до 256 символов.'); process.exit(1); }
  env.ADMV_PASSWORD_SALT = randomBytes(32).toString('hex');
  env.ADMV_PASSWORD_HASH = pbkdf2Sync(env.ADMV_PASSWORD, Buffer.from(env.ADMV_PASSWORD_SALT, 'hex'), 600000, 32, 'sha256').toString('hex');
  delete env.ADMV_PASSWORD; delete process.env.ADMV_PASSWORD;
}
if (env.ADMV_SESSION_KEY && env.ADMV_SESSION_KEY.length >= 32 && !/^[a-f0-9]{64}$/.test(env.ADMV_SESSION_KEY)) env.ADMV_SESSION_KEY = createHash('sha256').update(env.ADMV_SESSION_KEY).digest('hex');
const required = ['ADMV_LOGIN', 'ADMV_PASSWORD_HASH', 'ADMV_PASSWORD_SALT', 'ADMV_SESSION_KEY', 'ADMV_GITHUB_TOKEN'];
if (required.some(key => !env[key]) || !/^[a-f0-9]{64}$/.test(env.ADMV_PASSWORD_HASH || '') || !/^[a-f0-9]{32,128}$/.test(env.ADMV_PASSWORD_SALT || '') || env.ADMV_PASSWORD_SALT.length % 2 || !/^[a-f0-9]{64}$/.test(env.ADMV_SESSION_KEY || '')) { console.error('Не настроены серверные секреты ADMV.'); process.exit(1); }
const server = http.createServer(async (incoming, outgoing) => {
  try {
    if(incoming.method === 'GET' && incoming.url === '/health'){outgoing.writeHead(200, {'Content-Type':'application/json', 'Cache-Control':'no-store'});outgoing.end(JSON.stringify({ok:true}));return;}
    const request = new Request(new URL(incoming.url, 'http://localhost'), {
      method: incoming.method, headers: incoming.headers,
      ...(!['GET','HEAD'].includes(incoming.method) ? {body: Readable.toWeb(incoming), duplex: 'half'} : {})
    });
    const response = await handler.fetch(request, env);
    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch (_) {
    outgoing.writeHead(500, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'});
    outgoing.end(JSON.stringify({error: 'Сервер временно недоступен. Черновик сохранён.'}));
  }
});
server.requestTimeout = 30000;
server.headersTimeout = 10000;
server.maxRequestsPerSocket = 100;
server.listen(Number(process.env.PORT || 8787), process.env.HOST || '127.0.0.1', () => console.log('Сервер ADMV запущен.'));
