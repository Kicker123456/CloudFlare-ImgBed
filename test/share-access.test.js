import { test } from 'node:test';
import assert from 'node:assert/strict';
import { requireSharePassword } from '../functions/utils/shareAccess.js';

function fixture() {
    const records = new Map();
    const env = { img_url: { get: async key => records.get(key), put: async (key, value) => records.set(key, value) } };
    let reads = 0;
    const run = (options = {}, path = '/file/example.png?from=admin') => requireSharePassword({
        env, request: new Request('https://images.example' + path, options),
        next: async () => { reads++; return new Response('IMAGE', { headers: { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=31536000' } }); },
    });
    const login = password => run({ method: 'POST', headers: { Origin: 'https://images.example' }, body: new URLSearchParams({ sharePassword: password }) });
    return { run, login, records, env, reads: () => reads };
}

test('anonymous requests cannot reach images, including HEAD, Range and admin preview', async () => {
    const f = fixture();
    for (const options of [{}, { method: 'HEAD' }, { headers: { Range: 'bytes=0-10' } }, { headers: { Cookie: 'user_session=fake; admin_session=fake' } }]) {
        const res = await f.run(options);
        assert.equal(res.status, 401);
        assert.equal(res.headers.get('Cache-Control'), 'private, no-store');
        assert.equal(res.headers.get('Set-Cookie'), null);
    }
    assert.equal(f.reads(), 0);
});

test('wrong password and cross-origin submissions do not create sessions', async () => {
    const f = fixture();
    assert.equal((await f.login('wrong')).status, 401);
    assert.equal((await f.run({ method: 'POST', headers: { Origin: 'https://other.example' }, body: 'sharePassword=123' })).status, 403);
    assert.equal(f.records.size, 0);
    assert.equal(f.reads(), 0);
});

test('correct password persists viewing on other links without exposing the password or caching images publicly', async () => {
    const f = fixture();
    const res = await f.login('123');
    assert.equal(res.status, 303);
    assert.equal(res.headers.get('Location'), '/file/example.png?from=admin');
    const setCookie = res.headers.get('Set-Cookie');
    assert.match(setCookie, /HttpOnly; SameSite=Lax; Max-Age=31536000; Secure/);
    const cookie = setCookie.split(';')[0];
    assert.match(cookie, /^imgbed_share_session=[a-f0-9]{64}$/);
    for (const path of ['/file/another.webp', '/file/example.png']) {
        const image = await f.run({ headers: { Cookie: cookie } }, path);
        assert.equal(image.status, 200);
        assert.equal(await image.text(), 'IMAGE');
        assert.equal(image.headers.get('Cloudflare-CDN-Cache-Control'), 'no-store');
        assert.match(image.headers.get('Vary'), /Cookie/);
    }
    assert.equal(f.reads(), 2);
    assert.equal((await f.run()).status, 401);
});

test('expired, forged, malformed and password-rotated sessions are denied', async () => {
    const f = fixture();
    const res = await f.login('123');
    const cookie = res.headers.get('Set-Cookie').split(';')[0];
    const [key, value] = [...f.records][0];
    f.records.set(key, JSON.stringify({ ...JSON.parse(value), expiresAt: 0 }));
    assert.equal((await f.run({ headers: { Cookie: cookie } })).status, 401);
    f.records.set(key, '{bad');
    assert.equal((await f.run({ headers: { Cookie: cookie } })).status, 401);
    f.records.set(key, value);
    f.env.SHARE_PASSWORD_HASH = 'new-password';
    assert.equal((await f.run({ headers: { Cookie: cookie } })).status, 401);
    assert.equal((await f.run({ headers: { Cookie: 'imgbed_share_session=' + '0'.repeat(64) } })).status, 401);
    assert.equal(f.reads(), 0);
});

test('storage failure fails closed', async () => {
    const f = fixture();
    f.env.img_url.get = async () => { throw new Error('unavailable'); };
    assert.equal((await f.run({ headers: { Cookie: 'imgbed_share_session=' + 'a'.repeat(64) } })).status, 503);
    assert.equal(f.reads(), 0);
});
