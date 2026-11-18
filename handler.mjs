const encoder = new TextEncoder();
const hex = (bytes)=>Array.from(new Uint8Array(bytes), (b)=>b.toString(16).padStart(2, '0')).join('');
const unhex = (value)=>Uint8Array.from(value.match(/../g) || [], (b)=>parseInt(b, 16));
async function passwordDigest(password, salt) {
    const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, [
        'deriveBits'
    ]);
    return hex(await crypto.subtle.deriveBits({
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: unhex(salt),
        iterations: 600000
    }, key, 256));
}
async function equalDigest(left, right) {
    const key = await crypto.subtle.importKey('raw', encoder.encode('admv-constant-time-compare'), {
        name: 'HMAC',
        hash: 'SHA-256'
    }, false, [
        'sign',
        'verify'
    ]);
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(right));
    return crypto.subtle.verify('HMAC', key, signature, encoder.encode(left));
}
async function sessionKey(env) {
    return crypto.subtle.importKey('raw', unhex(env.ADMV_SESSION_KEY), {
        name: 'HMAC',
        hash: 'SHA-256'
    }, false, [
        'sign',
        'verify'
    ]);
}
async function issueSession(env) {
    const now = Math.floor(Date.now() / 1000), expires = now + 1800;
    const payload = btoa(JSON.stringify({
        aud: 'admv-admin',
        iat: now,
        exp: expires,
        nonce: crypto.randomUUID()
    })).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const signature = hex(await crypto.subtle.sign('HMAC', await sessionKey(env), encoder.encode(payload)));
    return {
        token: payload + '.' + signature,
        expires
    };
}
async function verifySession(token, env) {
    try {
        const parts = token.split('.');
        if (parts.length !== 2 || !/^[a-zA-Z0-9_-]{1,1000}$/.test(parts[0]) || !/^[a-f0-9]{64}$/.test(parts[1])) return false;
        if (!await crypto.subtle.verify('HMAC', await sessionKey(env), unhex(parts[1]), encoder.encode(parts[0]))) return false;
        const data = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'))), now = Math.floor(Date.now() / 1000);
        return data.aud === 'admv-admin' && Number.isInteger(data.iat) && Number.isInteger(data.exp) && data.iat <= now + 30 && data.exp > now && data.exp - data.iat === 1800;
    } catch (_) {
        return false;
    }
}
const origin = 'https://abubakarov-kerim.github.io';
const repo = 'abubakarov-kerim/admv-store';
const headers = {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers': 'authorization, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Vary': 'Origin',
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json'
};
const reply = (status, value)=>new Response(JSON.stringify(value), {
        status,
        headers
    });
class Failure extends Error {
    status;
    constructor(status, message){
        super(message), this.status = status;
    }
}
async function github(env, path, method = 'GET', body) {
    const response = await fetch('https://api.github.com/repos/' + repo + path, {
        method,
        signal: AbortSignal.timeout(20000),
        headers: {
            Authorization: 'Bearer ' + env.ADMV_GITHUB_TOKEN,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'ADMV-admin',
            'Content-Type': 'application/json'
        },
        body: body === undefined ? undefined : JSON.stringify(body)
    });
    if (!response.ok) throw new Failure(response.status === 409 || response.status === 422 ? 409 : 502, response.status === 409 || response.status === 422 ? 'Магазин уже обновился. Обновите страницу и повторите публикацию, сохранив резервную копию черновика.' : 'Не удалось опубликовать. Проверьте серверный ключ GitHub. Черновик сохранён.');
    return response.json();
}
export default {
    async fetch (request, env) {
        if (new URL(request.url).pathname !== '/admin') return reply(404, {
            error: 'Страница не найдена.'
        });
        if (request.headers.get('origin') !== origin) return reply(403, {
            error: 'Недопустимый источник запроса.'
        });
        if (request.method === 'OPTIONS') return new Response(null, {
            status: 204,
            headers
        });
        if (request.method !== 'POST') return reply(405, {
            error: 'Метод недоступен.'
        });
        try {
            if (!env.ADMV_LOGIN || !/^[a-f0-9]{64}$/.test(env.ADMV_PASSWORD_HASH || '') || !/^[a-f0-9]{32,128}$/.test(env.ADMV_PASSWORD_SALT || '') || env.ADMV_PASSWORD_SALT.length % 2 || !/^[a-f0-9]{64}$/.test(env.ADMV_SESSION_KEY || '') || !env.ADMV_GITHUB_TOKEN || !env.LOGIN_LIMITER) throw new Failure(503, 'Сервер входа ещё не настроен.');
            const declared = Number(request.headers.get('content-length'));
            if (declared > 20 * 1024 * 1024) throw new Failure(413, 'Слишком много фотографий за одну публикацию. Уменьшите размер фото.');
            const reader = request.body?.getReader();
            if (!reader) throw new Failure(400, 'Пустой запрос.');
            const chunks = [];
            let size = 0;
            while(true){
                const { done, value } = await reader.read();
                if (done) break;
                size += value.byteLength;
                if (size > 20 * 1024 * 1024) {
                    await reader.cancel();
                    throw new Failure(413, 'Слишком много фотографий за одну публикацию.');
                }
                chunks.push(value);
            }
            const bytes = new Uint8Array(size);
            let offset = 0;
            for (const chunk of chunks){
                bytes.set(chunk, offset);
                offset += chunk.length;
            }
            let body;
            try {
                body = JSON.parse(new TextDecoder().decode(bytes));
            } catch (_) {
                throw new Failure(400, 'Некорректный запрос.');
            }
            if (!body || typeof body !== 'object') throw new Failure(400, 'Некорректный запрос.');
            if (body.action === 'login') {
                if (size > 8192) throw new Failure(413, 'Слишком длинный запрос входа.');
                const { success } = await env.LOGIN_LIMITER.limit({
                    key: 'admv-owner-login'
                });
                if (!success) throw new Failure(429, 'Слишком много попыток. Подождите минуту и повторите.');
                if (typeof body.username !== 'string' || typeof body.password !== 'string' || body.username.length > 100 || body.password.length > 256) throw new Failure(401, 'Неверный логин или пароль.');
                const matches = await equalDigest(await passwordDigest(body.password, env.ADMV_PASSWORD_SALT), env.ADMV_PASSWORD_HASH);
                if (!matches || body.username.trim().toLowerCase() !== env.ADMV_LOGIN.toLowerCase()) throw new Failure(401, 'Неверный логин или пароль.');
                return reply(200, await issueSession(env));
            }
            const token = /^Bearer ([A-Za-z0-9._-]+)$/.exec(request.headers.get('authorization') || '')?.[1] || '';
            if (!await verifySession(token, env)) throw new Failure(401, 'Войдите в админку ещё раз.');
            if (body.action === 'logout') return reply(200, {
                ok: true
            });
            if (body.action !== 'publish') throw new Failure(400, 'Неизвестное действие.');
            const db = body.db, blobs = body.blobs;
            if (!db || !Array.isArray(db.products) || !Array.isArray(db.categories) || !db.store || typeof db.store !== 'object' || Array.isArray(db.store) || !Array.isArray(blobs) || blobs.length > 100 || db.products.length > 2000 || JSON.stringify(db).length > 2 * 1024 * 1024) throw new Failure(400, 'Некорректные данные магазина. Черновик сохранён.');
            const paths = new Set();
            for (const file of blobs){
                if (typeof file.path !== 'string' || !/^images\/p\/[a-zA-Z0-9_-]+\.(jpg|png|webp|gif)$/.test(file.path) || paths.has(file.path) || typeof file.b64 !== 'string' || file.b64.length > 8 * 1024 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(file.b64) || file.b64.length % 4) throw new Failure(400, 'Некорректный файл фотографии.');
                paths.add(file.path);
            }
            const ref = await github(env, '/git/ref/heads/main');
            const base = await github(env, '/git/commits/' + ref.object.sha);
            const tree = [];
            for (const file of blobs){
                const blob = await github(env, '/git/blobs', 'POST', {
                    content: file.b64,
                    encoding: 'base64'
                });
                tree.push({
                    path: file.path,
                    mode: '100644',
                    type: 'blob',
                    sha: blob.sha
                });
            }
            const saved = {
                ...db,
                _v: 2,
                _rev: Date.now(),
                _date: new Date().toISOString()
            };
            tree.push({
                path: 'data/db.json',
                mode: '100644',
                type: 'blob',
                content: JSON.stringify(saved, null, 1)
            });
            const nextTree = await github(env, '/git/trees', 'POST', {
                base_tree: base.tree.sha,
                tree
            });
            const commit = await github(env, '/git/commits', 'POST', {
                message: 'Публикация товаров из ADMV',
                tree: nextTree.sha,
                parents: [
                    ref.object.sha
                ]
            });
            await github(env, '/git/refs/heads/main', 'PATCH', {
                sha: commit.sha,
                force: false
            });
            return reply(200, {
                db: saved
            });
        } catch (error) {
            return reply(error instanceof Failure ? error.status : 500, {
                error: error instanceof Failure ? error.message : 'Сервер временно недоступен. Черновик сохранён.'
            });
        }
    }
};
