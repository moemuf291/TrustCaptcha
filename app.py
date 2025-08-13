import io
import os
import time
import uuid
import random
import string
import secrets
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

from flask import (
	Flask,
	render_template,
	request,
	redirect,
	url_for,
	session,
	make_response,
	abort,
	g,
)

from PIL import Image, ImageDraw, ImageFont, ImageFilter
try:
	from dotenv import load_dotenv, find_dotenv
	# First try loading from current working directory; fallback to script directory
	if not load_dotenv():
		_here = Path(__file__).resolve().parent
		load_dotenv(dotenv_path=_here / ".env", override=False)
except Exception:
	pass
import redis
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
logger = logging.getLogger("captcha_app")

# Debug flag early for secret/redis checks
IS_DEBUG = bool(int(os.getenv("FLASK_DEBUG", "0")))

# Secrets (optional for local/dev). If not provided, use an ephemeral key.
secret_from_env = os.getenv("SECRET_KEY") or os.getenv("FLASK_SECRET_KEY")
if secret_from_env:
	app.secret_key = secret_from_env
else:
	app.secret_key = secrets.token_urlsafe(32)
	logger.warning("SECRET_KEY not set; using ephemeral key (sessions reset on restart). Set SECRET_KEY for production.")

# CSRF
csrf = CSRFProtect(app)

# Config
CAPTCHA_TTL_SECONDS = 120
CAPTCHA_MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_SUBMISSIONS_PER_IP = 10
CAPTCHA_REFRESH_AFTER_FAILS = 2
CAPTCHA_IMAGE_WIDTH = 240
CAPTCHA_IMAGE_HEIGHT = 80
CAPTCHA_LENGTH = 6
CAPTCHA_OWNER_BIND_SESSION = True  # bind captcha to creator's session

# Security-related Flask config
app.config.update(
	SESSION_COOKIE_HTTPONLY=True,
	SESSION_COOKIE_SECURE=bool(int(os.getenv("SESSION_COOKIE_SECURE", "0"))),
	SESSION_COOKIE_SAMESITE="Strict",
	MAX_CONTENT_LENGTH=16 * 1024,
)

# Additional security controls (tunable via env)
SESSION_IDLE_TIMEOUT_SECONDS = int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "900"))
FORCE_HTTPS = bool(int(os.getenv("FORCE_HTTPS", "0")))
MIN_SUBMIT_PROCESSING_MS = int(os.getenv("MIN_SUBMIT_PROCESSING_MS", "150"))

# Brute force mitigation (bans); prefer library for rate limits
FAIL_WINDOW_SECONDS = int(os.getenv("FAIL_WINDOW_SECONDS", "300"))
FAILURES_BEFORE_TEMP_BLOCK = int(os.getenv("FAILURES_BEFORE_TEMP_BLOCK", "10"))
TEMP_BLOCK_SECONDS = int(os.getenv("TEMP_BLOCK_SECONDS", "300"))

# Redis client (set REDIS_URL). In prod, fail-fast if unavailable
REDIS_URL = os.getenv("REDIS_URL")
_redis_client: Optional[redis.Redis] = None

# In production mode, no in-memory fallback (kept only for debug)
CAPTCHA_STORE: Dict[str, Dict[str, Any]] = {}
SUBMISSION_LOG_BY_IP: Dict[str, List[float]] = {}
FAIL_LOG_BY_IP: Dict[str, List[float]] = {}
BANNED_IP_UNTIL: Dict[str, float] = {}



def _get_redis() -> Optional[redis.Redis]:
	global _redis_client
	if not REDIS_URL:
		# Optional: run without Redis; use in-memory fallback
		return None
	if _redis_client is None:
		try:
			_redis_client = redis.from_url(REDIS_URL, decode_responses=True)
			# Warm-up ping
			_redis_client.ping()
		except Exception as e:
			logger.exception("Redis connection failed")
			_redis_client = None
	return _redis_client


# Flask-Limiter setup (use Redis storage when available)
_limiter_storage_uri = None
if REDIS_URL:
	_limiter_storage_uri = f"{REDIS_URL}"
else:
	_limiter_storage_uri = "memory://"

limiter = Limiter(
	get_remote_address,
	app=app,
	storage_uri=_limiter_storage_uri,
	strategy="fixed-window",
)

AMBIGUOUS_CHARS = set("0O1IL")
CAPTCHA_ALPHABET = [c for c in string.ascii_uppercase + string.digits if c not in AMBIGUOUS_CHARS]


def _cleanup_expired():
	# Redis keys auto-expire; in-memory fallback cleanup
	client = _get_redis()
	if client is not None:
		return
	now = time.time()
	expired_keys = []
	for key, data in CAPTCHA_STORE.items():
		created = data.get("created_at", 0.0)
		used = data.get("used", False)
		if used or (now - created) > CAPTCHA_TTL_SECONDS:
			expired_keys.append(key)
	for key in expired_keys:
		CAPTCHA_STORE.pop(key, None)


def _generate_random_text(length: int = CAPTCHA_LENGTH) -> str:
	return "".join(random.choice(CAPTCHA_ALPHABET) for _ in range(length))


def _is_under(child: Path, parent: Path) -> bool:
	try:
		child.resolve().relative_to(parent.resolve())
		return True
	except Exception:
		return False


def _pick_font(size: int = 42) -> ImageFont.ImageFont:
	# Use bundled fonts only (immutable)
	here = Path(__file__).resolve().parent
	candidates = [
		here / "assets" / "fonts" / "DejaVuSans.ttf",
		Path.cwd() / "assets" / "fonts" / "DejaVuSans.ttf",
		Path.cwd() / "captcha" / "assets" / "fonts" / "DejaVuSans.ttf",
	]
	for path in candidates:
		try:
			if path.is_file():
				return ImageFont.truetype(str(path), size=size)
		except Exception as e:
			logger.exception("Font load failed for %s", path)
			continue
	return ImageFont.load_default()


def _draw_noise(draw: ImageDraw.ImageDraw, width: int, height: int) -> None:
	for _ in range(400):
		x = random.randint(0, width - 1)
		y = random.randint(0, height - 1)
		color = (random.randint(150, 220), random.randint(150, 220), random.randint(150, 220))
		draw.point((x, y), fill=color)
	for _ in range(8):
		start = (random.randint(0, width), random.randint(0, height))
		end = (random.randint(0, width), random.randint(0, height))
		color = (random.randint(100, 180), random.randint(100, 180), random.randint(100, 180))
		draw.line([start, end], fill=color, width=random.randint(1, 3))


def _warp_affine(image: Image.Image) -> Image.Image:
	w, h = image.size
	shear_x = random.uniform(-0.2, 0.2)
	shear_y = random.uniform(-0.1, 0.1)
	angle = random.uniform(-5, 5)
	image = image.rotate(angle, resample=Image.BICUBIC, expand=0)
	affine_matrix = (1, shear_x, 0, shear_y, 1, 0)
	return image.transform((w, h), Image.AFFINE, affine_matrix, resample=Image.BICUBIC)


def _render_captcha_image(text: str) -> bytes:
	width = CAPTCHA_IMAGE_WIDTH
	height = CAPTCHA_IMAGE_HEIGHT
	background_color = (245, 246, 248)
	image = Image.new("RGB", (width, height), background_color)
	draw = ImageDraw.Draw(image)

	_draw_noise(draw, width, height)

	font = _pick_font(size=42)

	total_text_width = 0
	char_sizes = []
	for ch in text:
		size = draw.textlength(ch, font=font)
		char_sizes.append(size)
		total_text_width += size

	x = (width - total_text_width - (len(text) - 1) * 8) / 2
	y_center = height // 2

	for ch, ch_width in zip(text, char_sizes):
		angle = random.uniform(-25, 25)
		ch_image = Image.new("RGBA", (int(ch_width) + 20, 60), (255, 255, 255, 0))
		ch_draw = ImageDraw.Draw(ch_image)
		ch_color = (random.randint(20, 80), random.randint(20, 80), random.randint(20, 80))
		ch_draw.text((10, 10), ch, font=font, fill=ch_color)
		ch_image = ch_image.rotate(angle, resample=Image.BICUBIC, expand=1)
		jx = random.randint(-2, 2)
		jy = random.randint(-5, 5)
		image.paste(ch_image, (int(x + jx), int(y_center - ch_image.size[1] // 2 + jy)), ch_image)
		x += ch_width + 8

	image = _warp_affine(image)
	image = image.filter(ImageFilter.SMOOTH_MORE)
	image = image.filter(ImageFilter.EDGE_ENHANCE_MORE)

	draw = ImageDraw.Draw(image)
	for _ in range(8):
		rx = random.randint(0, width)
		ry = random.randint(0, height)
		rw = random.randint(30, 60)
		rh = random.randint(5, 15)
		color = (random.randint(150, 210), random.randint(150, 210), random.randint(150, 210))
		draw.arc([rx, ry, rx + rw, ry + rh], start=random.randint(0, 360), end=random.randint(0, 360), fill=color, width=1)

	out = io.BytesIO()
	image.save(out, format="PNG", optimize=True)
	return out.getvalue()


def _new_captcha(session_id: str) -> str:
	_cleanup_expired()
	captcha_id = uuid.uuid4().hex
	text = _generate_random_text()
	client = _get_redis()
	if client is not None:
		try:
			key = f"captcha:{captcha_id}"
			pipe = client.pipeline()
			pipe.hset(key, mapping={
				"answer": text.lower(),
				"created_at": str(time.time()),
				"attempts": "0",
				"used": "0",
				"owner_session": session_id if CAPTCHA_OWNER_BIND_SESSION else "",
			})
			pipe.expire(key, CAPTCHA_TTL_SECONDS)
			pipe.execute()
		except Exception as e:
			logger.exception("Redis error creating captcha")
			client = None
	if client is None:
		CAPTCHA_STORE[captcha_id] = {
			"answer": text.lower(),
			"created_at": time.time(),
			"attempts": 0,
			"used": False,
			"owner_session": session_id if CAPTCHA_OWNER_BIND_SESSION else None,
		}
	return captcha_id


def _read_captcha(captcha_id: str) -> Optional[Dict[str, Any]]:
	client = _get_redis()
	if client is not None:
		try:
			key = f"captcha:{captcha_id}"
			data = client.hgetall(key)
			if not data:
				return None
			# Normalize types
			return {
				"answer": (data.get("answer") or "").lower(),
				"created_at": float(data.get("created_at", "0") or 0),
				"attempts": int(data.get("attempts", "0") or 0),
				"used": (data.get("used") == "1"),
				"owner_session": data.get("owner_session") or None,
			}
		except Exception as e:
			logger.exception("Redis error reading captcha %s", captcha_id)
			client = None
	if client is None:
		return CAPTCHA_STORE.get(captcha_id)


def _set_captcha_field(captcha_id: str, field: str, value: Any) -> None:
	client = _get_redis()
	if client is not None:
		try:
			key = f"captcha:{captcha_id}"
			# Keep TTL alive; do not change here
			client.hset(key, field, str(int(value)) if isinstance(value, bool) else str(value))
			return
		except Exception as e:
			logger.exception("Redis error setting field %s on captcha %s", field, captcha_id)
			client = None
	if client is None:
		if captcha_id in CAPTCHA_STORE:
			CAPTCHA_STORE[captcha_id][field] = value


def _delete_captcha(captcha_id: str) -> None:
	client = _get_redis()
	if client is not None:
		try:
			client.delete(f"captcha:{captcha_id}")
			return
		except Exception as e:
			logger.exception("Redis error deleting captcha %s", captcha_id)
			client = None
	if client is None:
		CAPTCHA_STORE.pop(captcha_id, None)


# Flask-WTF CSRF is enabled globally; use generate_csrf() when rendering forms


def _rate_limit_check(ip: str) -> bool:
	# Deprecated in favor of Flask-Limiter; keep as no-op allowed path
	return True


def _is_ip_banned(ip: str) -> bool:
	client = _get_redis()
	if client is not None:
		try:
			return client.exists(f"banned:{ip}") == 1
		except Exception:
			client = None
	# Fallback in-memory
	now = time.time()
	until = BANNED_IP_UNTIL.get(ip, 0.0)
	return now < until


def _register_failure(ip: str) -> None:
	now = time.time()
	client = _get_redis()
	if client is not None:
		try:
			key = f"failures:{ip}"
			cutoff = now - FAIL_WINDOW_SECONDS
			pipe = client.pipeline()
			pipe.zadd(key, {str(now): now})
			pipe.zremrangebyscore(key, 0, cutoff)
			pipe.zcard(key)
			pipe.expire(key, FAIL_WINDOW_SECONDS)
			_, _, count, _ = pipe.execute()
			if int(count) >= FAILURES_BEFORE_TEMP_BLOCK:
				client.setex(f"banned:{ip}", TEMP_BLOCK_SECONDS, "1")
			return
		except Exception:
			client = None
	# Fallback in-memory
	window_start = now - FAIL_WINDOW_SECONDS
	entries = FAIL_LOG_BY_IP.get(ip, [])
	entries = [t for t in entries if t >= window_start]
	entries.append(now)
	FAIL_LOG_BY_IP[ip] = entries
	if len(entries) >= FAILURES_BEFORE_TEMP_BLOCK:
		BANNED_IP_UNTIL[ip] = now + TEMP_BLOCK_SECONDS


def _incremental_delay_seconds(ip: str) -> float:
	# Removed blocking sleeps; return 0
	return 0.0


def _client_ip() -> str:
	if os.getenv("TRUST_PROXY", "0") == "1":
		xff = request.headers.get("X-Forwarded-For", "")
		if xff:
			return xff.split(",")[0].strip()
	return request.remote_addr or "unknown"


@app.route("/", methods=["GET"])
def index():
	if "sid" not in session:
		session["sid"] = uuid.uuid4().hex
	captcha_id = _new_captcha(session["sid"])
	# Provide a CSP nonce for inline styles
	nonce = secrets.token_urlsafe(16)
	g.csp_nonce = nonce
	resp = make_response(render_template("form.html", captcha_id=captcha_id, error_message=None, csrf_token=generate_csrf()))
	resp.headers["Content-Security-Policy"] = f"default-src 'self'; img-src 'self' data:; style-src 'self' 'nonce-{nonce}'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
	return resp


@app.route("/captcha/<captcha_id>.png", methods=["GET"])
def captcha_image(captcha_id: str):
	data = _read_captcha(captcha_id)
	if not data:
		abort(404)
	if CAPTCHA_OWNER_BIND_SESSION:
		if "sid" not in session or session.get("sid") != data.get("owner_session"):
			abort(403)
	age = time.time() - data["created_at"]
	if age > CAPTCHA_TTL_SECONDS or data.get("used"):
		abort(410)
	image_bytes = _render_captcha_image(data["answer"])
	resp = make_response(image_bytes)
	resp.headers["Content-Type"] = "image/png"
	resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
	resp.headers["Pragma"] = "no-cache"
	return resp


@app.route("/submit", methods=["POST"])
@limiter.limit("10/minute")
def submit():
	client_ip = _client_ip()

	def _pad_and_return(resp, status_code: int = None):
		return resp if status_code is None else (resp, status_code)

	# Temporary block check
	if _is_ip_banned(client_ip):
		captcha_id = _new_captcha(session.get("sid", uuid.uuid4().hex))
		resp = make_response(render_template(
			"form.html",
			captcha_id=captcha_id,
			error_message="Too many recent failures. Please wait and try again.",
			csrf_token=_new_csrf_token(),
		))
		resp.headers["Retry-After"] = str(TEMP_BLOCK_SECONDS)
		return _pad_and_return(resp, 429)

	# CSRF is enforced by Flask-WTF; extra check for defense-in-depth
	# Flask-WTF already validates CSRF; this extra check ensures token is present
	if not request.form.get("csrf_token"):
		_register_failure(client_ip)
		captcha_id = _new_captcha(session.get("sid", uuid.uuid4().hex))
		return _pad_and_return(render_template(
			"form.html",
			captcha_id=captcha_id,
			error_message="Invalid or missing form token. Please try again.",
			csrf_token=_new_csrf_token(),
		), 400)

	# Rate limiting handled by Flask-Limiter

	captcha_id = request.form.get("captcha_id", "")
	user_answer = (request.form.get("captcha_answer") or "").strip().lower()

	data = _read_captcha(captcha_id)
	if not data:
		_register_failure(client_ip)
		new_id = _new_captcha(session.get("sid", uuid.uuid4().hex))
		return _pad_and_return(render_template(
			"form.html",
			captcha_id=new_id,
			error_message="Your CAPTCHA expired or is invalid. Please try a new one.",
			csrf_token=_new_csrf_token(),
		), 400)

	if CAPTCHA_OWNER_BIND_SESSION:
		if "sid" not in session or session.get("sid") != data.get("owner_session"):
			_register_failure(client_ip)
			_delete_captcha(captcha_id)
			new_id = _new_captcha(session.get("sid", uuid.uuid4().hex))
			return _pad_and_return(render_template(
				"form.html",
				captcha_id=new_id,
				error_message="This CAPTCHA is not valid for your session. Please try again.",
				csrf_token=_new_csrf_token(),
			), 403)

	if (time.time() - data["created_at"]) > CAPTCHA_TTL_SECONDS or data.get("used"):
		_register_failure(client_ip)
		_delete_captcha(captcha_id)
		new_id = _new_captcha(session["sid"])
		return _pad_and_return(render_template(
			"form.html",
			captcha_id=new_id,
			error_message="Your CAPTCHA expired. Please try again.",
			csrf_token=_new_csrf_token(),
		), 400)

	# increment attempts atomically if possible
	client = _get_redis()
	if client is not None:
		try:
			client.hincrby(f"captcha:{captcha_id}", "attempts", 1)
			data["attempts"] += 1
		except Exception:
			data["attempts"] += 1
	else:
		data["attempts"] += 1
	if data["attempts"] > CAPTCHA_MAX_ATTEMPTS:
		_register_failure(client_ip)
		_delete_captcha(captcha_id)
		new_id = _new_captcha(session["sid"])
		return _pad_and_return(render_template(
			"form.html",
			captcha_id=new_id,
			error_message="Too many incorrect attempts. A new CAPTCHA was generated.",
			csrf_token=_new_csrf_token(),
		), 400)

	if user_answer != data["answer"]:
		_register_failure(client_ip)
		# Optionally refresh CAPTCHA after a few failures for this token
		if CAPTCHA_REFRESH_AFTER_FAILS and (data["attempts"] % CAPTCHA_REFRESH_AFTER_FAILS == 0):
			_delete_captcha(captcha_id)
			new_id = _new_captcha(session["sid"]) 
			return _pad_and_return(render_template(
				"form.html",
				captcha_id=new_id,
				error_message="Incorrect answer. A new CAPTCHA was generated.",
				csrf_token=_new_csrf_token(),
			), 400)
		return _pad_and_return(render_template(
			"form.html",
			captcha_id=captcha_id,
			error_message="CAPTCHA answer was incorrect. Please try again.",
			csrf_token=_new_csrf_token(),
		), 400)

	# Success
	_set_captcha_field(captcha_id, "used", True)
	_delete_captcha(captcha_id)
	# Regenerate our logical session id after sensitive validation to reduce fixation risk
	session["sid"] = uuid.uuid4().hex
	return _pad_and_return(redirect(url_for("success")))


@app.after_request
def add_security_headers(resp):
	"""Add security headers to all responses to reduce XSS and related risks."""
	# A restrictive CSP is set on the index response with a per-request nonce
	resp.headers.setdefault("X-Content-Type-Options", "nosniff")
	resp.headers.setdefault("X-Frame-Options", "DENY")
	resp.headers.setdefault("Referrer-Policy", "no-referrer")
	resp.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
	resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
	resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
	# HSTS when HTTPS is enforced/active
	if FORCE_HTTPS or request.is_secure or request.headers.get("X-Forwarded-Proto", "").lower() == "https":
		resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	return resp


@app.before_request
def security_before_request():
	# Optional HTTPS redirect
	if FORCE_HTTPS:
		is_secure = request.is_secure or request.headers.get("X-Forwarded-Proto", "").lower() == "https"
		if not is_secure:
			url = request.url.replace("http://", "https://", 1)
			return redirect(url, code=308)

	# Session idle timeout
	now = time.time()
	last = session.get("last_activity")
	if last and (now - float(last)) > SESSION_IDLE_TIMEOUT_SECONDS:
		session.clear()
		session["sid"] = uuid.uuid4().hex
		session["csrf_token"] = secrets.token_urlsafe(32)
	session["last_activity"] = now


@app.route("/success", methods=["GET"])
def success():
	return "Form submitted successfully with a valid CAPTCHA.", 200


if __name__ == "__main__":
	debug = bool(int(os.getenv("FLASK_DEBUG", "0")))
	host = os.getenv("FLASK_RUN_HOST", "127.0.0.1")
	port = int(os.getenv("FLASK_RUN_PORT", "5000"))
	app.run(host=host, port=port, debug=debug)