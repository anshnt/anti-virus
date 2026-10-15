"""Authenticated single-user loopback HTTP service; never expose this to a LAN."""
import hmac
import json
import mimetypes
import os
import secrets
import threading
import time
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .core import DATA, ROOT, Engine, now
from . import windows
from . import startup

VERSION = '2.0.0-dev'
STATIC = {'/': 'index.html', '/app.css': 'app.css', '/app.js': 'app.js'}


def equal_secret(given, expected):
    return isinstance(given, str) and len(given) <= 200 and hmac.compare_digest(given.encode('utf-8'), expected.encode('utf-8'))


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, engine, metadata=True):
        super().__init__(address, Handler)
        self.engine = engine
        self.session = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(32)
        self.auth_lock = threading.Lock()
        self.expires = 0
        self.metadata = metadata
        self.host = f'127.0.0.1:{self.server_port}'
        self.origin = f'http://{self.host}'
        self.persist()

    def persist(self):
        if self.metadata:
            temp = self.engine.store.folder / 'instance.tmp'
            temp.write_text(json.dumps({'pid': os.getpid(), 'port': self.server_port, 'nonce': self.nonce, 'version': VERSION}), encoding='utf-8')
            os.replace(temp, self.engine.store.folder / 'instance.json')


class Handler(BaseHTTPRequestHandler):
    server_version = 'SentinelLocal'
    sys_version = ''
    protocol_version = 'HTTP/1.0'

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        # Bootstrap URLs contain a one-use local secret. Never log request targets.
        pass

    def reply(self, status, value, content_type='application/json; charset=utf-8', extra=None):
        if status >= 400 and self.command == 'POST' and not getattr(self, '_body_consumed', False):
            self.discard_small_body()
        data = json.dumps(value, ensure_ascii=True).encode('utf-8') if content_type.startswith('application/json') else value
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def discard_small_body(self):
        # A Windows close with unread request bytes can reset the connection and
        # discard the error response. Drain only a small bounded body, with a
        # short timeout, before rejecting; never wait for an arbitrarily large
        # or deliberately incomplete body.
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if 0 < length <= 131072 and not self.headers.get('Transfer-Encoding'):
                self.connection.settimeout(0.1)
                while length > 0:
                    block = self.rfile.read1(min(length, 16384))
                    if not block:
                        break
                    length -= len(block)
        except (ValueError, OSError):
            pass
        finally:
            self._body_consumed = True
            self.connection.settimeout(10)

    def gate(self, mutation=False):
        if self.headers.get_all('Host') != [self.server.host]:
            self.reply(403, {'error': 'This app accepts only its exact local address.'})
            return False
        origin = self.headers.get('Origin')
        if (origin and origin != self.server.origin) or self.headers.get('Sec-Fetch-Site') == 'cross-site':
            self.reply(403, {'error': 'Cross-site requests are blocked.'})
            return False
        if mutation and origin != self.server.origin:
            self.reply(403, {'error': 'A local app origin is required.'})
            return False
        return True

    def authenticated(self):
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', ''))
            token = cookie['sentinel_session'].value
            valid = equal_secret(token, self.server.session) and time.time() < self.server.expires
        except (KeyError, ValueError, CookieError):
            valid = False
        if not valid:
            self.reply(401, {'error': 'Open the app using Start Sentinel Local.cmd to begin a local session.'})
        return valid

    def do_GET(self):
        if not self.gate():
            return
        parsed = urlsplit(self.path)
        route = parsed.path
        if parsed.query or parsed.fragment:
            return self.reply(404, {'error': 'Unknown route.'})
        if route == '/health':
            return self.reply(200, {'app': 'Sentinel Local', 'version': VERSION, 'pid': os.getpid()})
        if route.startswith('/open/'):
            with self.server.auth_lock:
                token = route.removeprefix('/open/')
                if not equal_secret(token, self.server.nonce):
                    return self.reply(401, {'error': 'This launch link has expired. Run the launcher again.'})
                self.server.nonce = secrets.token_urlsafe(32)
                self.server.expires = time.time() + 8 * 3600
                self.server.persist()
            # Cookies are shared across ports. A separate token, delivered only by
            # this one-use bootstrap, protects APIs even if another local service
            # receives a loopback cookie. URL fragments never reach HTTP logs.
            return self.reply(303, b'', 'text/plain', {'Location': '/#session=' + self.server.csrf, 'Set-Cookie': f'sentinel_session={self.server.session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'})
        if not self.authenticated():
            return
        if route in STATIC:
            name = STATIC[route]
            content_type = {'index.html': 'text/html', 'app.js': 'text/javascript', 'app.css': 'text/css'}[name] + '; charset=utf-8'
            return self.reply(200, (ROOT / 'web' / name).read_bytes(), content_type)
        if route.startswith('/api/') and not equal_secret(self.headers.get('X-CSRF-Token', ''), self.server.csrf):
            return self.reply(403, {'error': 'Reopen Start Sentinel Local.cmd to establish this browser tab’s private session.'})
        if route == '/api/state':
            state = self.server.engine.status()
            state['version'] = VERSION
            state['hashes'] = self.server.engine.store.get('hashes', [])
            state['startupLaunch'] = startup.status()
            return self.reply(200, state)
        if route == '/api/export':
            report = self.server.engine.status()
            report['exportedAt'] = now()
            report['scope'] = 'Local security console evidence; no guarantee that all malware is absent. Review-only alerts are not malware verdicts.'
            return self.reply(200, report, extra={'Content-Disposition': 'attachment; filename="Sentinel-Local-security-report.json"'})
        self.reply(404, {'error': 'Unknown route.'})

    def do_POST(self):
        if not self.gate(mutation=True) or not self.authenticated():
            return
        if not equal_secret(self.headers.get('X-CSRF-Token', ''), self.server.csrf):
            return self.reply(403, {'error': 'Invalid local session token. Reopen the launcher.'})
        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type') != 'application/json':
            return self.reply(415, {'error': 'A JSON request is required.'})
        try:
            lengths = self.headers.get_all('Content-Length') or []
            if len(lengths) != 1:
                raise ValueError()
            length = int(lengths[0])
            if not 0 < length <= 65536:
                raise ValueError()
        except ValueError:
            return self.reply(413, {'error': 'Request body must be between 1 and 65,536 bytes.'})
        try:
            raw = self.rfile.read(length)
            self._body_consumed = True
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError('A JSON object is required.')
            route = self.path
            engine = self.server.engine
            if route == '/api/refresh':
                engine.refresh()
                result = {'ok': True}
            elif route == '/api/job':
                result = {'id': engine.job(body.get('kind'), body.get('path'))}
            elif route == '/api/integrity/add':
                engine.integrity_add(body.get('path'))
                result = {'ok': True}
            elif route == '/api/integrity/remove':
                if not isinstance(body.get('path'), str):
                    raise ValueError('Choose a watched file.')
                engine.integrity_remove(body['path'])
                result = {'ok': True}
            elif route == '/api/settings':
                engine.settings(body)
                result = {'ok': True}
            elif route == '/api/antivirus/policy':
                engine.antivirus_policy(body)
                result = {'ok': True}
            elif route == '/api/startup':
                if set(body) != {'enabled'}:
                    raise ValueError('Invalid sign-in launch request.')
                startup.configure(body['enabled'], engine.store)
                result = {'ok': True}
            elif route == '/api/antivirus/cancel':
                if not engine.antivirus.active_scan:
                    raise ValueError('No independent scan is active.')
                engine.antivirus.cancel.set()
                result = {'ok': True}
            elif route == '/api/quarantine':
                result = {'id': engine.vault_action('quarantine', body.get('id'))}
            elif route == '/api/quarantine/recover':
                result = {'path': engine.vault_action('recover', body.get('id'))}
            elif route == '/api/windows-security':
                windows.open_security()
                result = {'ok': True}
            elif route == '/api/quit':
                engine.request_stop()
                engine.store.log('Console stopped', 'Defender protection continues independently.')
                result = {'ok': True}
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                return self.reply(404, {'error': 'Unknown action.'})
            self.reply(200, result)
        except (ValueError, OSError) as exc:
            self.reply(400, {'error': str(exc)})
        except Exception:
            self.reply(500, {'error': 'The action failed. Check Windows Security or restart the app after any running scan finishes.'})


def serve():
    engine = Engine()
    try:
        server = LocalServer(('127.0.0.1', 8769), engine)
    except OSError:
        server = LocalServer(('127.0.0.1', 0), engine)
    try:
        server.serve_forever(poll_interval=0.3)
    finally:
        engine.stop.set()
        server.server_close()
        try:
            (engine.store.folder / 'instance.json').unlink()
        except FileNotFoundError:
            pass
