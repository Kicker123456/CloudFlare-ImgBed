import { getDatabase } from './databaseAdapter.js';
import { verifyPassword, generateSessionToken } from './auth/passwordHash.js';

// Override SHARE_PASSWORD_HASH when rotating the viewing password.
const DEFAULT_PASSWORD_HASH = '$pbkdf2$eb81a0c886512ec93a135050025bb64e$ef8daf2d15910ab3e2439762a08d8089115810228a7a4bf46bec257a2bf8d893';
const COOKIE = 'imgbed_share_session';
const PREFIX = 'manage@shareSession@';
const MAX_AGE = 365 * 24 * 60 * 60;

function privateResponse(response) {
    const headers = new Headers(response.headers);
    headers.set('Cache-Control', 'private, no-store');
    headers.set('CDN-Cache-Control', 'no-store');
    headers.set('Cloudflare-CDN-Cache-Control', 'no-store');
    headers.append('Vary', 'Cookie');
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function passwordPage(request, error = '', status = 401) {
    const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>输入密码查看图片</title><style>
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6fa;color:#202938;font-family:system-ui,sans-serif;padding:24px}main{width:100%;max-width:380px;background:white;padding:36px 28px;border-radius:20px;box-shadow:0 12px 40px #15234012}h1{font-size:23px;margin:0 0 12px}p{font-size:14px;color:#697386;line-height:1.7}label{display:block;font-size:14px;margin:24px 0 8px}input,button{width:100%;padding:14px;border-radius:10px;font:inherit}input{border:1px solid #ced5df}input:focus{outline:2px solid #a4bdf8}button{border:0;background:#386be8;color:white;margin-top:16px;cursor:pointer}.error{color:#bf3030;min-height:24px;margin-bottom:0}</style></head><body><main><h1>输入密码查看图片</h1><p><strong>访问密码：123</strong></p><p>验证后将自动记住此浏览器，之后打开分享链接无需重复输入。</p><form method="post"><label for="password">访问密码</label><input id="password" name="sharePassword" type="password" autocomplete="current-password" required maxlength="256" autofocus><button type="submit">查看图片</button><p class="error" role="alert">${error}</p></form></main></body></html>`;
    return privateResponse(new Response(request.method === 'HEAD' ? null : html, { status, headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
    } }));
}

// Runs before every file handler, including R2 and the application edge cache.
// Share sessions only grant image viewing; they do not grant upload/admin access.
export async function requireSharePassword(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const passwordHash = env.SHARE_PASSWORD_HASH || DEFAULT_PASSWORD_HASH;
    try {
        const db = getDatabase(env);
        const match = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)imgbed_share_session=([a-f0-9]{64})(?:;|$)/);
        if (match && (request.method === 'GET' || request.method === 'HEAD')) {
            const stored = await db.get(PREFIX + match[1]);
            let session;
            try { session = stored ? JSON.parse(stored) : null; } catch { session = null; }
            if (session?.passwordHash === passwordHash && session.expiresAt > Date.now()) {
                return privateResponse(await context.next());
            }
        }

        if (request.method === 'POST') {
            if (request.headers.get('Origin') !== url.origin) {
                return passwordPage(request, '请重新打开分享链接后输入密码。', 403);
            }
            const body = await request.text();
            if (body.length > 2048) return passwordPage(request, '密码过长。', 400);
            const password = new URLSearchParams(body).get('sharePassword');
            if (!password || password.length > 256 || !await verifyPassword(password, passwordHash)) {
                return passwordPage(request, '密码不正确，请重试。');
            }
            const token = generateSessionToken();
            await db.put(PREFIX + token, JSON.stringify({ passwordHash, expiresAt: Date.now() + MAX_AGE * 1000 }), { expirationTtl: MAX_AGE });
            return privateResponse(new Response(null, { status: 303, headers: {
                Location: url.pathname + url.search,
                'Set-Cookie': `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${MAX_AGE}${url.protocol === 'https:' ? '; Secure' : ''}`,
            } }));
        }
        return passwordPage(request);
    } catch (error) {
        console.error('Share access unavailable:', error.message);
        return passwordPage(request, '暂时无法验证，请稍后重试。', 503);
    }
}
