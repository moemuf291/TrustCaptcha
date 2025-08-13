# TrustCaptcha

A simple, framework-agnostic CAPTCHA you can drop into any website. It renders an obfuscated image and validates user input with single-use tokens, TTL, and attempt limits. Works with standard HTML forms (POST) — no JavaScript required.

## Features
- No JavaScript (pure HTML form submission)
- Obfuscated image (noise, rotation, distortion)
- Single-use token, TTL expiration, attempt caps
- Optional session binding and IP rate limiting
- CSRF protection (Flask‑WTF)
- Security headers (CSP with nonce, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- HTTPS/HSTS support via environment flags
- Rate limiting (Flask‑Limiter, default 10/min on POST /submit) and temporary IP blocks with Retry‑After
- Accessible labels and clear, generic error messages
- Bundled font loading with safe path handling (no external font paths)

## Quickstart

Requirements:
- Python 3.9+
- `pip install -r requirements.txt`

Optional (recommended for production):
- Redis 6+ (local or managed). Set `REDIS_URL` to connect.
  - Note: Fail-fast is NOT enabled by default. If Redis is missing/unreachable, the app falls back to in-memory storage (not durable, not shared across processes). Enable Redis for production.
- Create a `.env` file in the project root; variables are auto-loaded via python-dotenv.

Run:
```bash
python app.py
```
Visit: `http://127.0.0.1:5000/`

Environment variables (optional):
- `FLASK_DEBUG=1` to enable debug locally
- `FLASK_RUN_HOST=0.0.0.0` and `FLASK_RUN_PORT=5000` to customize bind
- `SESSION_COOKIE_SECURE=1` in production (requires HTTPS)
- `FORCE_HTTPS=1` to redirect HTTP→HTTPS and enable HSTS
- Place these into `.env` to avoid setting them per shell session.

## Project layout
app.py
requirements.txt
templates/
form.html
assets/
fonts/
DejaVuSans.ttf (optional; or set CAPTCHA_FONT_PATH)


## How it works
- Server generates a unique `captcha_id` per form render and stores:
  - `answer`, `created_at`, `attempts`, `used`, `owner_session`
- Image endpoint `/captcha/<captcha_id>.png` renders a distorted PNG for the stored answer
- POST handler validates:
  - `captcha_id` exists, not expired, not used
  - attempts ≤ limit, session matches (if enabled)
  - user’s answer (case-insensitive)
- On success: invalidate token and proceed; on failure: re-render with an error

## Integrating into your website

### 1) Drop-in HTML (no JS)
Add this to your form template (server fills `<CAPTCHA_ID>`):
```html
<form method="post" action="/submit">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
  <div>
    <img src="/captcha/<CAPTCHA_ID>.png" alt="CAPTCHA image" width="240" height="80" />
    <a href="/">Get a new image</a>
  </div>
  <label for="captcha_answer">Type the characters you see</label>
  <input id="captcha_answer" name="captcha_answer" type="text" required />
  <input type="hidden" name="captcha_id" value="<CAPTCHA_ID>" />
  <button type="submit">Submit</button>
</form>
```

### 2) Backend routes you need (any framework/language)
- GET form route (`/form` or `/`):
  - Generate `captcha_id`, store `{answer, created_at, attempts, used, owner_session}`
  - Render form with hidden `captcha_id` and `<img src="/captcha/<captcha_id>.png">`
- GET `/captcha/<captcha_id>.png`:
  - Look up stored data, enforce TTL/single-use/session binding
  - Render obfuscated PNG; set no-cache headers
- POST `/submit`:
  - Read `captcha_id` + `captcha_answer`
  - Validate existence/TTL/attempts/session binding
  - Compare answers (case-insensitive), invalidate on success, handle errors

Using the provided Flask app (`app.py` + `templates/form.html`) gives you these routes out of the box:
- GET `/` (form)
- GET `/captcha/<captcha_id>.png` (image)
- POST `/submit` (validation)
- GET `/success` (demo success page)

## Configuration (in app.py)
```python
CAPTCHA_TTL_SECONDS = 120
CAPTCHA_MAX_ATTEMPTS = 5
CAPTCHA_REFRESH_AFTER_FAILS = 2  # set to 0 to disable auto-refresh on repeated fails
CAPTCHA_IMAGE_WIDTH = 240
CAPTCHA_IMAGE_HEIGHT = 80
CAPTCHA_LENGTH = 6
CAPTCHA_OWNER_BIND_SESSION = True
```

Security-related config and environment variables:
- Cookies and sessions
  - `SESSION_COOKIE_HTTPONLY=True` (default)
  - `SESSION_COOKIE_SAMESITE="Strict"` (default)
  - `SESSION_COOKIE_SECURE` via env (set `1` in production over HTTPS)
  - `SESSION_IDLE_TIMEOUT_SECONDS` via env (default 900)
- HTTPS and headers
  - `FORCE_HTTPS` via env (default 0): redirects HTTP→HTTPS; enables HSTS when secure
  - Global headers: CSP (nonce is set per request on `/`), X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/CORP
- Request handling
  - `MAX_CONTENT_LENGTH=16KB` (default)
- Brute-force mitigation (env tunables)
  - `FAIL_WINDOW_SECONDS` (default 300)
  - `FAILURES_BEFORE_TEMP_BLOCK` (default 10)
  - `TEMP_BLOCK_SECONDS` (default 300)
- App serving
  - `FLASK_DEBUG`, `FLASK_RUN_HOST`, `FLASK_RUN_PORT`
 - Rate limiting
   - Default limit is set in code via `@limiter.limit("10/minute")` on the `/submit` route.

Redis settings:
- `REDIS_URL` (e.g., `redis://:password@127.0.0.1:6379/0` or `rediss://...` for TLS)
  - CAPTCHAs stored as hashes: `captcha:<id>` with fields `answer`, `created_at`, `attempts`, `used`, `owner_session` and a TTL via EXPIRE
  - Rate limiting stored in ZSETs: `rate:<ip>` with timestamps; window enforced via `ZREMRANGEBYSCORE` and `EXPIRE`
  - Failure tracking stored in ZSETs: `failures:<ip>`; incremental delays use recent count
  - Temporary bans stored as keys: `banned:<ip>` with `SETEX`
  - In dev, leaving `REDIS_URL` unset is okay (in-memory fallback). For production, configure Redis.

## Fonts
- Uses bundled `assets/fonts/DejaVuSans.ttf` if present; otherwise falls back to Pillow’s default font.
- External font paths via env are not used for security and portability.

DejaVuSans is a good free option: `assets/fonts/DejaVuSans.ttf` (optional).
If you include the font in your repo, follow its license.

## Production notes
- Replace in-memory stores with Redis or your datastore
- Set a strong `SECRET_KEY` (env). Without it, the app generates an ephemeral key and sessions reset on restart
- Serve over HTTPS; set cookie flags (Secure, HttpOnly); consider `FORCE_HTTPS=1`
- Keep images non-cacheable
- Consider stricter rate limiting at proxy/load balancer
- Keep TTL short; consider increasing distortion/length if too easy
- Consider adding alternative CAPTCHA modes (audio/math) for accessibility
- Secure Redis: require auth, enable TLS (`rediss://`), firewall off public internet, allow-only from app network/VPC.
- Verify keys with `redis-cli`:
  - `KEYS captcha:*` / `HGETALL captcha:<id>`
  - `ZRANGE rate:<ip> 0 -1 WITHSCORES`
  - `EXISTS banned:<ip>` and check TTL with `TTL banned:<ip>`

## Troubleshooting
- Image 404/410: token missing/expired/used — render a new one
- Always failing: verify storage keys, TTL, session binding
- Font warnings: set `CAPTCHA_FONT_PATH` or add a `.ttf` to `assets/fonts/`
- Difficulty: adjust `CAPTCHA_LENGTH`, noise, and distortion parameters

## License
This sample code is provided as-is. If you bundle third-party fonts (e.g., DejaVu), comply with their licenses.

