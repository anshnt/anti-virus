import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import windows

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get('LOCALAPPDATA', str(ROOT))) / 'SentinelLocal'
MAX_HASH = 256 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


def file_path(raw, directory=False):
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 240:
        raise ValueError('Enter a full local Windows path, up to 240 characters.')
    raw = raw.strip().strip('"')
    if any(ord(c) < 32 for c in raw) or raw.startswith(('\\\\', '//')) or ':' in raw[2:]:
        raise ValueError('Network, device and alternate-stream paths are not supported.')
    path = Path(raw)
    if not path.is_absolute() or not re.match(r'^[A-Za-z]:[\\/]', raw):
        raise ValueError('Use an absolute local drive path, for example C:\\Users\\YourName\\Downloads\\file.exe.')
    # Check every component before resolving: a reparse point could lead to a network share.
    for item in [*reversed(path.parents), path]:
        info = item.lstat()
        attrs = getattr(info, 'st_file_attributes', 0)
        if attrs & (0x400 | 0x1000 | 0x40000 | 0x400000) or item.is_symlink():
            raise ValueError('Reparse points, offline and cloud placeholder paths are skipped to avoid following or downloading content.')
    path = path.resolve(strict=True)
    if not path.is_file() and not (directory and path.is_dir()):
        raise ValueError('Choose an existing regular file' + (' or folder.' if directory else '.'))
    return path


def digest(path, limit=MAX_HASH):
    info = path.stat()
    if info.st_size > limit:
        raise ValueError(f'File exceeds the {limit // 1024 // 1024} MB hashing limit. Use a Defender custom scan instead.')
    value = hashlib.sha256()
    count = 0
    with path.open('rb') as handle:
        while block := handle.read(1024 * 1024):
            count += len(block)
            if count > limit:
                raise ValueError('File grew beyond the hashing limit during inspection.')
            value.update(block)
    after = path.stat()
    if (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('The file changed while being read. Try again after it finishes writing.')
    return value.hexdigest()


PATTERNS = [
    ('Encoded PowerShell command', r'(?i)(?:powershell|pwsh)[^\r\n]{0,180}-(?:enc|encodedcommand)\s'),
    ('Download followed by execution', r'(?is)(?:downloadstring|invoke-webrequest|iwr\s|wget\s).{0,500}(?:invoke-expression|\biex\b|start-process)'),
    ('Attempts to delete recovery copies', r'(?i)(?:vssadmin|wmic)[^\r\n]{0,180}(?:delete\s+shadows|shadowcopy\s+delete)'),
    ('Attempts to disable security monitoring', r'(?i)set-mppreference[^\r\n]{0,200}-disable(?:realtime|behavior|ioav|script)'),
    ('Script decoder or dynamic execution', r'(?i)(?:frombase64string\s*\(|eval\s*\(|execute\s*\(|invoke-expression\s)'),
]


def script_indicators(path):
    if path.suffix.lower() not in {'.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.py'}:
        return []
    with path.open('rb') as handle:
        raw = handle.read(1024 * 1024)
    encoding = 'utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
    text = raw.decode(encoding, errors='replace')
    return [label for label, pattern in PATTERNS if re.search(pattern, text)]


def event_field(event, key):
    norm = lambda s: re.sub(r'[^a-z0-9]', '', s.lower())
    return next((str(v) for k, v in event.get('fields', {}).items() if norm(k) == norm(key)), '')


def scan_result(events, before_records, kind, exit_code):
    # Completion must belong to this exact scan. A successful process exit or
    # FullScanEndTime can coexist with cancellation (for example RPC rundown).
    fresh = [e for e in events if e.get('record') not in before_records]
    starts = [e for e in fresh if e['id'] == 1000 and kind.lower() in event_field(e, 'Scan Parameters').lower()]
    if len(starts) != 1:
        return 'unverified', 'No unique matching scan-start event was available; the command exit code alone does not prove completion.'
    scan_id = event_field(starts[0], 'Scan ID')
    finish = [e for e in fresh if e['id'] in (1001, 1002, 1005) and event_field(e, 'Scan ID') == scan_id and scan_id]
    if any(e['id'] == 1002 for e in finish):
        return 'interrupted', 'Defender recorded scan cancellation. ' + next((event_field(e, 'Stop Reason') for e in finish if e['id'] == 1002), '')
    if any(e['id'] == 1005 for e in finish):
        return 'failed', 'Defender recorded a scan failure.'
    if any(e['id'] == 1001 for e in finish) and exit_code == 0:
        return 'completed', 'Defender recorded a matching scan-completed event. Review detections separately; completion is not a guarantee that every threat is absent.'
    if any(e['id'] == 1001 for e in finish):
        return 'unverified', f'A completion event exists but the command returned {exit_code}; review Windows Protection History.'
    return 'unverified', f'No matching completion event was found (command exit {exit_code}).'


class Store:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.db = self.folder / 'sentinel.sqlite3'
        with self.connect() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, kind TEXT, status TEXT, created TEXT, finished TEXT, detail TEXT, result TEXT);
            CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY, time TEXT, level TEXT, title TEXT, detail TEXT);
            CREATE TABLE IF NOT EXISTS integrity(path TEXT PRIMARY KEY, hash TEXT, lastHash TEXT, status TEXT, checked TEXT);
            ''')

    @contextmanager
    def connect(self):
        # sqlite's transaction context does not close the connection. Explicitly
        # close it so monitor threads do not leak handles or lock Windows files.
        c = sqlite3.connect(self.db, timeout=10)
        c.row_factory = sqlite3.Row
        try:
            with c:
                yield c
        finally:
            c.close()

    def get(self, key, default=None):
        with self.connect() as c:
            row = c.execute('SELECT value FROM kv WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        with self.connect() as c:
            c.execute('INSERT OR REPLACE INTO kv VALUES (?,?)', (key, json.dumps(value)))

    def log(self, title, detail='', level='info'):
        with self.connect() as c:
            c.execute('INSERT INTO activity(time,level,title,detail) VALUES(?,?,?,?)', (now(), level, title, detail))
            c.execute('DELETE FROM activity WHERE id NOT IN (SELECT id FROM activity ORDER BY id DESC LIMIT 1500)')

    def rows(self, query, args=()):
        with self.connect() as c:
            return [dict(r) for r in c.execute(query, args).fetchall()]


class Engine:
    def __init__(self, folder=DATA, start=True):
        self.store = Store(folder)
        # Recover jobs only when starting an engine, not whenever a read-only
        # store client opens the database during installation or diagnostics.
        with self.store.connect() as c:
            c.execute("UPDATE jobs SET status='unverified',finished=?,detail='The app restarted before a verified result was saved. Review engine evidence.' WHERE status IN ('running','queued')", (now(),))
        self.lock = threading.Lock()
        self.scan_lock = threading.Lock()
        self.snapshot_lock = threading.Lock()
        self.stop = threading.Event()
        self.snapshot = self.store.get('snapshot', {'sections': {}, 'checkedAt': None})
        self.refreshing = False
        self.refresh_error = None
        self.event_error = None
        self.events = self.store.get('events', [])
        self.last_watch = None
        self.watch_error = None
        self.started = now()
        from .antivirus import Antivirus
        from .vault import Vault
        self.antivirus = Antivirus(self.store)
        self.antivirus.cleanup_staging()
        self.vault = Vault(self.store)
        self.vault.reconcile()
        from .selftest import SelfTest
        self.selftest = SelfTest(self.antivirus)
        from .cleaner import Cleaner
        self.cleaner = Cleaner(self.store)
        self.pending_downloads = {}
        self.store.log('Console started', 'Local monitoring runs while this app is open. Defender protection runs independently.')
        if start:
            threading.Thread(target=self._monitor, daemon=True).start()
            self.refresh()

    def refresh(self):
        if not self.snapshot_lock.acquire(blocking=False):
            return False
        self.refreshing = True
        threading.Thread(target=self._refresh, daemon=True).start()
        return True

    def _refresh(self):
        try:
            snap = windows.snapshot()
            snap['checkedAt'] = now()
            self.snapshot = snap
            self.store.set('snapshot', snap)
            self.refresh_error = None
            self._startup_changes(snap)
            self._events()
        except Exception as exc:
            self.refresh_error = str(exc)
        finally:
            self.refreshing = False
            self.snapshot_lock.release()

    def _events(self):
        try:
            self.events = windows.events()
            self.store.set('events', self.events)
            self.event_error = None
        except Exception as exc:
            self.event_error = str(exc)

    def _startup_changes(self, snap):
        s = snap.get('sections', {}).get('startup', {})
        if not s.get('ok'):
            return
        current = sorted((s.get('data') or []), key=lambda r: (r.get('Name') or '', r.get('Location') or ''))
        old = self.store.get('startup_last')
        if old is not None and old != current:
            self.store.log('Startup entries changed', 'Review the Persistence page. Changes may be caused by normal installation or updates.', 'review')
        self.store.set('startup_last', current)

    def status(self):
        jobs = self.store.rows('SELECT * FROM jobs ORDER BY created DESC LIMIT 50')
        for j in jobs:
            j['result'] = json.loads(j['result']) if j['result'] else None
        return {'snapshot': self.snapshot, 'refreshing': self.refreshing, 'refreshError': self.refresh_error,
                'events': self.events, 'eventError': self.event_error, 'jobs': jobs,
                'activity': self.store.rows('SELECT * FROM activity ORDER BY id DESC LIMIT 150'),
                'integrity': self.store.rows('SELECT * FROM integrity ORDER BY path'),
                'settings': self.store.get('settings', {'watchDownloads': True}),
                'antivirus': self.antivirus.status(), 'cleaner': self.cleaner.status(),
                'selfTest': {'progress': self.selftest.progress},
                'monitor': {'lastChecked': self.last_watch, 'error': self.watch_error, 'running': not self.stop.is_set()},
                'started': self.started, 'downloadFolder': str(Path.home() / 'Downloads'), 'dataFolder': str(self.store.folder)}

    def job(self, kind, raw=None, _background=False):
        if kind not in {'quick', 'full', 'custom', 'update', 'inspect', 'av-install', 'av-update', 'av-quick', 'av-full', 'av-custom', 'av-watch', 'av-selftest'}:
            raise ValueError('Unsupported action.')
        if kind == 'av-watch' and not _background:
            raise ValueError('Download watch scans are created only by the local monitor.')
        path = file_path(raw, directory=(kind in {'custom', 'av-custom'})) if kind in {'inspect', 'custom', 'av-custom'} else raw if kind == 'av-watch' else None
        if kind == 'inspect' and path.stat().st_size > MAX_HASH:
            raise ValueError('File exceeds 256 MB. Use a custom Defender scan instead.')
        with self.lock:
            if self.stop.is_set():
                raise ValueError('The console is stopping. Reopen the launcher before starting a scan.')
            if not self.scan_lock.acquire(blocking=False):
                raise ValueError('Another scan, update or inspection is in progress. Wait for its result.')
        job_id = uuid.uuid4().hex
        try:
            with self.store.connect() as c:
                c.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)', (job_id, kind, 'running', now(), None, 'Independent antivirus operation in progress.' if kind.startswith('av-') else 'Working. Scan completion is verified using Defender events.', None))
            threading.Thread(target=self._job, args=(job_id, kind, path), daemon=True).start()
        except Exception:
            self.scan_lock.release()
            raise
        return job_id

    def request_stop(self):
        with self.lock:
            if self.scan_lock.locked() or self.cleaner.busy:
                raise ValueError('A scan, update, inspection or cleanup is running. Let it finish before quitting. Closing this browser tab is fine.')
            self.stop.set()

    def _job(self, job_id, kind, path):
        result = None
        try:
            self.store.log('Started ' + kind, str(path) if path else '')
            if kind.startswith('av-'):
                if kind == 'av-selftest':
                    result = self.selftest.run()
                    state = result['status']
                    detail = 'Harmless isolated diagnostic ' + state + f" in {result['seconds']} seconds. No malware benchmark or whole-PC safety claim."
                elif kind == 'av-install':
                    result = self.antivirus.install()
                    state, detail = 'completed', 'Independent ClamAV engine installed. Update its signatures before scanning.'
                elif kind == 'av-update':
                    result = self.antivirus.update()
                    state, detail = 'completed', 'Official independent-engine signatures updated and validated by FreshClam.'
                else:
                    if kind == 'av-quick':
                        roots = windows.priority_folders()
                    elif kind == 'av-full':
                        roots = windows.local_drives()
                    else:
                        roots = path if kind == 'av-watch' else [path]
                    if not roots:
                        raise ValueError('No supported local scan roots were found.')
                    result = self.antivirus.scan(job_id, roots)
                    state = result['status']
                    detail = f"Independent scan {state}: {result['scanned']} files scanned, {result['detected']} findings, {result['skipped']} skipped, {result['errors']} errors."
            elif kind == 'inspect':
                sha = digest(path)
                result = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha,
                          'signature': windows.signature(path), 'indicators': script_indicators(path),
                          'hashMatch': sha in self.store.get('hashes', []),
                          'note': 'Static review only. A valid signature is not a safety guarantee; an unsigned file is not proof of malware. Script checks inspect the first 1 MB.'}
                state, detail = 'completed', 'File inspected without executing it. Run a custom Defender scan for a malware verdict.'
            else:
                # Require fresh event evidence; stale cached events cannot validate a new scan.
                before = windows.events()
                if kind != 'update':
                    terminal = {event_field(e, 'Scan ID') for e in before if e['id'] in (1001, 1002, 1005)}
                    active = [e for e in before if e['id'] == 1000 and event_field(e, 'Scan ID') not in terminal and
                              (datetime.now(timezone.utc) - datetime.fromisoformat(e['time'].replace('Z', '+00:00'))).total_seconds() < 48 * 3600]
                    if active:
                        raise ValueError('A Defender scan may already be active. Let it finish or review Windows Security before starting another.')
                code = windows.run_defender(kind, path)
                if kind == 'update':
                    state = 'completed' if code == 0 else 'failed'
                    detail = 'Defender signature update command completed.' if code == 0 else f'Defender update returned {code}. Review Windows Security.'
                    result = {'exitCode': code}
                else:
                    after = windows.events()
                    state, detail = scan_result(after, {e['record'] for e in before}, kind, code)
                    if state == 'unverified':
                        # Allow the event service a short time to flush the result.
                        time.sleep(3)
                        after = windows.events()
                        state, detail = scan_result(after, {e['record'] for e in before}, kind, code)
                    result = {'exitCode': code, 'eventRecords': [e for e in after if e['record'] not in {x['record'] for x in before} and e['id'] in (1000, 1001, 1002, 1005, 1116, 1117, 1118)]}
                    self.events = after
                    self.store.set('events', after)
            self.store.log(kind.title() + ': ' + state, detail, 'review' if state != 'completed' else 'info')
        except Exception as exc:
            state, detail = 'failed', str(exc)
            self.store.log(kind.title() + ' failed', detail, 'review')
        finally:
            with self.store.connect() as c:
                c.execute('UPDATE jobs SET status=?,finished=?,detail=?,result=? WHERE id=?', (state, now(), detail, json.dumps(result), job_id))
            self.scan_lock.release()
            self.refresh()

    def integrity_add(self, raw):
        if len(self.store.rows('SELECT path FROM integrity')) >= 16:
            raise ValueError('The local integrity watch supports up to 16 files.')
        path = file_path(raw)
        sha = digest(path, 64 * 1024 * 1024)
        with self.store.connect() as c:
            c.execute('INSERT OR REPLACE INTO integrity VALUES(?,?,?,?,?)', (str(path), sha, sha, 'unchanged', now()))
        self.store.log('Integrity baseline saved', str(path))

    def integrity_remove(self, path):
        with self.store.connect() as c:
            c.execute('DELETE FROM integrity WHERE path=?', (path,))

    def settings(self, body):
        if set(body) != {'watchDownloads', 'hashes'} or not isinstance(body['watchDownloads'], bool):
            raise ValueError('Invalid settings.')
        hashes = body['hashes']
        if not isinstance(hashes, list) or len(hashes) > 200 or any(not isinstance(h, str) or not re.fullmatch('[a-fA-F0-9]{64}', h) for h in hashes):
            raise ValueError('Enter at most 200 SHA-256 hashes, with exactly 64 hexadecimal characters each.')
        self.store.set('hashes', sorted(set(h.lower() for h in hashes)))
        self.store.set('settings', {'watchDownloads': body['watchDownloads']})
        self.store.log('Settings saved', 'Download monitoring ' + ('enabled' if body['watchDownloads'] else 'disabled'))

    def antivirus_policy(self, body):
        if set(body) != {'scanDownloads', 'autoUpdate'} or not all(isinstance(v, bool) for v in body.values()):
            raise ValueError('Invalid antivirus policy.')
        self.store.set('antivirus_policy', body)
        self.store.log('Independent antivirus policy saved', 'Download scans ' + ('on' if body['scanDownloads'] else 'off') + '; automatic signature updates ' + ('on' if body['autoUpdate'] else 'off'))

    def vault_action(self, action, item_id):
        with self.lock:
            if self.stop.is_set():
                raise ValueError('The console is stopping.')
            if not self.scan_lock.acquire(blocking=False):
                raise ValueError('Wait for the current scan or update before changing quarantine.')
        try:
            if self.stop.is_set():
                raise ValueError('The console is stopping.')
            return self.vault.quarantine(item_id) if action == 'quarantine' else self.vault.recover(item_id)
        finally:
            self.scan_lock.release()

    def _antivirus_background(self):
        status = self.antivirus.status()
        if not status['installed'] or self.scan_lock.locked() or self.stop.is_set():
            return
        policy = self.antivirus.policy()
        last_attempt = self.store.get('antivirus_update_attempt', 0)
        if not last_attempt and status['lastUpdate']:
            last_attempt = datetime.fromisoformat(status['lastUpdate']).timestamp()
        if policy['autoUpdate'] and time.time() - last_attempt > 6 * 3600:
            self.store.set('antivirus_update_attempt', time.time())
            self.job('av-update')
            return
        if policy['scanDownloads'] and status['definitionsReady']:
            ready = [p for p, changed in self.pending_downloads.items() if time.time() - changed >= 10][:32]
            if ready:
                self.job('av-watch', ready, _background=True)
                for p in ready:
                    self.pending_downloads.pop(p, None)

    def _monitor(self):
        tick = 0
        while not self.stop.is_set():
            try:
                if self.store.get('settings', {'watchDownloads': True})['watchDownloads']:
                    self._downloads()
                self._integrity()
                self._antivirus_background()
                self.last_watch = now()
                self.watch_error = None
            except Exception as exc:
                self.watch_error = str(exc)
            tick += 1
            if tick % 12 == 0:
                self.refresh()
            self.stop.wait(20)

    def _downloads(self):
        folder = Path.home() / 'Downloads'
        # Non-recursive, bounded watch. Never follows links or hydrates cloud files.
        if not folder.exists():
            raise ValueError('The default Downloads folder was not found. Download monitoring is unavailable.')
        file_path(str(folder), directory=True)
        previous = self.store.get('downloads')
        current = {}
        count = 0
        with os.scandir(folder) as entries:
            for entry in entries:
                count += 1
                if count > 6000:
                    raise ValueError('Downloads contains over 6,000 entries; the watch is paused. Defender still protects the PC.')
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & (0x400 | 0x1000 | 0x40000 | 0x400000):
                    continue
                stamp = [info.st_size, info.st_mtime_ns]
                current[entry.name] = stamp
                if previous is not None and previous.get(entry.name) != stamp and Path(entry.name).suffix.lower() not in {'.crdownload', '.part', '.tmp'}:
                    if len(self.pending_downloads) < 128:
                        self.pending_downloads[str(folder / entry.name)] = time.time()
                    else:
                        self.store.log('Automatic scan queue is full', 'Scan Center can scan Downloads manually. New changes are still reviewable.', 'review')
                if previous is not None and previous.get(entry.name) != stamp and Path(entry.name).suffix.lower() in {'.exe', '.msi', '.ps1', '.bat', '.cmd', '.js', '.vbs', '.scr', '.dll', '.hta', '.lnk'}:
                    self.store.log('Executable or script arrived / changed', str(folder / entry.name) + ' — review alert, not a malware detection. Inspect or scan it in Scan Center.', 'review')
        self.store.set('downloads', current)

    def _integrity(self):
        for row in self.store.rows('SELECT * FROM integrity'):
            try:
                sha = digest(file_path(row['path']), 64 * 1024 * 1024)
                state = 'unchanged' if sha == row['hash'] else 'changed'
                if sha != row['lastHash']:
                    self.store.log('Watched file content changed', row['path'], 'review')
            except Exception:
                state, sha = 'unavailable', row['lastHash']
                if row['status'] != 'unavailable':
                    self.store.log('Watched file unavailable', row['path'], 'review')
            with self.store.connect() as c:
                c.execute('UPDATE integrity SET lastHash=?,status=?,checked=? WHERE path=?', (sha, state, now(), row['path']))
