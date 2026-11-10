// Site-wide password gate. Every request needs a valid gate cookie, otherwise
// the password page is served. The password lives in the `site_password`
// Worker secret; changing it invalidates every existing cookie.

const COOKIE = 'cm_gate';
const GATE_PATH = '/__gate';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days
// Paths that skip the gate. /api/init/:secret is already protected by jwt_secret
// and is called by the GitHub deploy workflow.
const EXEMPT = ['/api/init/'];

const enc = new TextEncoder();

async function sign(password, msg) {
	const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const sig = await crypto.subtle.sign('HMAC', key, enc.encode(msg));
	return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function safeEqual(a, b) {
	if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}

function readCookie(req, name) {
	const header = req.headers.get('Cookie') || '';
	for (const part of header.split(';')) {
		const [k, ...v] = part.trim().split('=');
		if (k === name) return v.join('=');
	}
	return null;
}

function safeNext(next) {
	return typeof next === 'string' && next.startsWith('/') && !/^\/[\/\\]/.test(next) && !next.includes('\\') ? next : '/';
}

function page(next, error) {
	const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Protected</title>
<style>
:root{--bg:#f4f5f7;--card:#fff;--text:#1f2328;--muted:#656d76;--border:#d0d7de;--accent:#1f6feb;--err:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--text:#e6edf3;--muted:#8d96a0;--border:#30363d;--accent:#2f81f7;--err:#f85149}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;padding:16px}
form{width:100%;max-width:340px;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:28px}
h1{font-size:18px;margin:0 0 4px}p{margin:0 0 20px;color:var(--muted);font-size:14px}
input{width:100%;padding:10px 12px;font:inherit;color:var(--text);background:var(--bg);border:1px solid var(--border);border-radius:8px}
input:focus{outline:2px solid var(--accent);outline-offset:-1px}
button{width:100%;margin-top:12px;padding:10px;font:inherit;font-weight:600;color:#fff;background:var(--accent);border:0;border-radius:8px;cursor:pointer}
.err{color:var(--err);font-size:13px;margin:10px 0 0}
</style></head><body>
<form method="post" action="${GATE_PATH}">
<h1>Private site</h1><p>Enter the access password to continue.</p>
<input type="hidden" name="next" value="${esc(next)}">
<input type="password" name="password" placeholder="Password" autocomplete="current-password" autofocus required>
${error ? '<div class="err">Incorrect password.</div>' : ''}
<button type="submit">Continue</button>
</form></body></html>`;
}

function html(body, status = 200, extra = {}) {
	return new Response(body, {
		status,
		headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex', ...extra },
	});
}

// Returns a Response when the request must be stopped, or null to let it through.
export async function gate(req, env) {
	const url = new URL(req.url);
	const password = env.site_password;

	if (EXEMPT.some((p) => url.pathname.startsWith(p))) return null;

	if (!password) {
		return new Response('Site password is not configured.', { status: 503 });
	}

	const expected = await sign(password, 'cloud-mail-gate-v1');

	if (url.pathname === GATE_PATH && req.method === 'POST') {
		const form = await req.formData().catch(() => null);
		const next = safeNext(form?.get('next'));
		const given = form?.get('password');
		if (typeof given === 'string' && safeEqual(await sign(password, given), await sign(password, password))) {
			return new Response(null, {
				status: 303,
				headers: {
					Location: next,
					'Set-Cookie': `${COOKIE}=${expected}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`,
					'Cache-Control': 'no-store',
				},
			});
		}
		await new Promise((r) => setTimeout(r, 1000)); // slow down guessing
		return html(page(next, true), 401);
	}

	if (safeEqual(readCookie(req, COOKIE), expected)) {
		return url.pathname === GATE_PATH ? Response.redirect(new URL('/', url).toString(), 303) : null;
	}

	if (url.pathname.startsWith('/api/')) {
		return new Response(JSON.stringify({ code: 401, message: 'Site password required' }), {
			status: 401,
			headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
		});
	}

	return html(page(safeNext(url.pathname + url.search), false), 401);
}
