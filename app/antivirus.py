"""Independent antivirus engine. Official ClamAV binaries and signed CVD updates.

Untrusted samples are scanned by a separate CLI process, never loaded into the
HTTP server. A verdict is not inferred from script patterns or publisher names.
"""
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .core import file_path, now

VERSION = '1.5.4'
ARCHIVE_SHA256 = '0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395'
ARCHIVE_BYTES = 225774978
ARCHIVE_URL = f'https://github.com/Cisco-Talos/clamav/releases/download/clamav-{VERSION}/clamav-{VERSION}.win.x64.zip'
MAX_FILE = 256 * 1024 * 1024
MAX_FILES = 1000000
FLAGS = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
SKIP_ATTRIBUTES = 0x400 | 0x1000 | 0x40000 | 0x400000


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def archive_member(name):
    p = PurePosixPath(name.replace('\\', '/'))
    if p.is_absolute() or '..' in p.parts or any(':' in part or part.endswith(('.', ' ')) for part in p.parts):
        raise ValueError('Unsafe path in engine archive.')
    return p


def classify_scan(code, findings, errors, skipped=0, cancelled=False):
    if cancelled:
        return 'cancelled'
    if code not in (0, 1) or errors:
        return 'partial' if findings else 'failed'
    if code == 1 and not findings:
        return 'unverified'
    if skipped or any(f['verdict'] == 'limited' for f in findings):
        return 'partial'
    return 'completed'


class Antivirus:
    def __init__(self, store):
        self.store = store
        self.root = store.folder / 'antivirus'
        self.runtime = self.root / ('clamav-' + VERSION)
        self.database = self.root / 'database'
        self.staging = self.root / 'staging'
        self.progress = None
        self.process_lock = threading.Lock()
        self.cancel = threading.Event()
        self.active_scan = False
        with store.connect() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS detections(id TEXT PRIMARY KEY, job TEXT, time TEXT, path TEXT, signature TEXT, sha256 TEXT, verdict TEXT, status TEXT);
            CREATE TABLE IF NOT EXISTS vault(id TEXT PRIMARY KEY, detection TEXT, time TEXT, path TEXT, sha256 TEXT, bytes INTEGER, status TEXT, recovery TEXT);
            CREATE TABLE IF NOT EXISTS vault_checks(id TEXT PRIMARY KEY, checked TEXT, detail TEXT);
            ''')
        self.root.mkdir(exist_ok=True)
        self.staging.mkdir(exist_ok=True)

    def cleanup_staging(self):
        # Files left by a forced stop are never treated as completed results.
        # Only the single-instance owner calls this on startup. Opening a second
        # library/installer client must not remove an active scanner's snapshots.
        for path in [*self.staging.glob('*.scan'), *self.staging.glob('*.list')]:
            try:
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            except OSError:
                pass

    def policy(self):
        return self.store.get('antivirus_policy', {'scanDownloads': True, 'autoUpdate': True})

    def status(self):
        installed = (self.runtime / 'runtime-manifest.json').is_file()
        databases = [p for p in self.database.glob('*') if p.suffix in ('.cvd', '.cld')]
        daily = next((p for p in databases if p.stem == 'daily'), None)
        age = (time.time() - daily.stat().st_mtime) / 3600 if daily else None
        return {'engine': 'ClamAV', 'version': VERSION, 'installed': installed,
                'definitionsReady': any(p.stem == 'main' for p in databases) and daily is not None,
                'definitionAgeHours': round(age, 1) if age is not None else None,
                'lastUpdate': self.store.get('antivirus_last_update'),
                'updateError': self.store.get('antivirus_update_error'), 'policy': self.policy(),
                'progress': self.progress, 'activeScan': self.active_scan,
                'preExecutionBlocking': False,
                'detections': self.store.rows('SELECT * FROM detections ORDER BY time DESC LIMIT 200'),
                'vault': self.store.rows('SELECT v.*,c.checked,c.detail AS restartDetail FROM vault v LEFT JOIN vault_checks c ON v.id=c.id ORDER BY v.time DESC LIMIT 200')}

    def install(self, archive=None):
        if os.name != 'nt' or os.environ.get('PROCESSOR_ARCHITECTURE', '').upper() not in ('AMD64', 'X86_64'):
            raise ValueError('The pinned independent engine currently requires 64-bit Intel/AMD Windows.')
        if (self.runtime / 'runtime-manifest.json').exists():
            self.verify()
            return {'installed': True, 'version': VERSION, 'alreadyPresent': True}
        download = self.root / 'engine-download.zip'
        temporary = self.root / ('install-' + uuid.uuid4().hex)
        try:
            if archive is None:
                self.progress = {'phase': 'Downloading official engine', 'bytes': 0, 'totalBytes': ARCHIVE_BYTES}
                with urllib.request.urlopen(ARCHIVE_URL, timeout=60) as source, download.open('wb') as target:
                    count = 0
                    while block := source.read(1024 * 1024):
                        count += len(block)
                        if count > ARCHIVE_BYTES:
                            raise ValueError('The engine download exceeded its pinned release size.')
                        target.write(block)
                        self.progress['bytes'] = count
                archive = download
            archive = Path(archive)
            if archive.stat().st_size != ARCHIVE_BYTES or sha256(archive) != ARCHIVE_SHA256:
                raise ValueError('Official ClamAV release SHA-256 mismatch. Nothing was executed.')
            self.progress = {'phase': 'Verifying and installing engine'}
            temporary.mkdir()
            with zipfile.ZipFile(archive) as z:
                members = z.infolist()
                if len(members) > 5000 or sum(m.file_size for m in members) > 1500 * 1024 * 1024:
                    raise ValueError('Engine archive exceeds extraction limits.')
                for member in members:
                    relative = archive_member(member.filename)
                    if stat.S_ISLNK(member.external_attr >> 16):
                        raise ValueError('Engine archive links are not permitted.')
                    destination = temporary.joinpath(*relative.parts)
                    if member.is_dir():
                        destination.mkdir(parents=True, exist_ok=True)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        with z.open(member) as source, destination.open('xb') as target:
                            shutil.copyfileobj(source, target, 1024 * 1024)
            scanners = list(temporary.rglob('clamscan.exe'))
            if len(scanners) != 1:
                raise ValueError('Engine archive has no unique scanner executable.')
            base = scanners[0].parent
            files = {p.relative_to(base).as_posix(): sha256(p) for p in base.rglob('*') if p.is_file() and p.suffix.lower() in ('.exe', '.dll', '.crt', '.pem')}
            if 'freshclam.exe' not in files or 'clamscan.exe' not in files:
                raise ValueError('Required official engine programs are missing.')
            (base / 'runtime-manifest.json').write_text(json.dumps({'archiveSha256': ARCHIVE_SHA256, 'files': files}), encoding='utf-8')
            base.rename(self.runtime)
            self.verify()
            self.store.log('Independent engine installed', 'ClamAV ' + VERSION + '; official archive SHA-256 verified before extraction.')
            return {'installed': True, 'version': VERSION, 'archiveSha256': ARCHIVE_SHA256}
        finally:
            # Delete only owned staging paths below the app's private engine root.
            if (temporary.exists() and temporary.parent == self.root and not temporary.is_symlink()
                    and temporary.resolve().is_relative_to(self.root.resolve())):
                shutil.rmtree(temporary)
            if download.is_file():
                download.unlink()
            self.progress = None

    def verify(self):
        manifest = json.loads((self.runtime / 'runtime-manifest.json').read_text(encoding='utf-8'))
        if manifest.get('archiveSha256') != ARCHIVE_SHA256 or not manifest.get('files'):
            raise ValueError('Independent engine provenance is missing. Reinstall the engine.')
        for name, expected in manifest['files'].items():
            relative = archive_member(name)
            path = self.runtime.joinpath(*relative.parts)
            if path.is_symlink() or not path.is_file() or sha256(path) != expected:
                raise ValueError('Independent engine files changed. Execution blocked; reinstall the engine.')
        return self.runtime / 'clamscan.exe'

    def _run(self, args, on_line, cancellable=False):
        env = os.environ.copy()
        env.update({'LC_ALL': 'C', 'LANG': 'C'})
        with subprocess.Popen(args, cwd=self.runtime, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              creationflags=FLAGS, env=env, shell=False) as proc:
            done = threading.Event()
            def cancel_worker():
                while not done.wait(0.2):
                    if self.cancel.is_set():
                        if proc.poll() is None:
                            proc.terminate()
                        break
            if cancellable:
                threading.Thread(target=cancel_worker, daemon=True).start()
            try:
                while raw := proc.stdout.readline(65536):
                    on_line(raw.decode('utf-8', errors='replace').rstrip())
                return proc.wait()
            finally:
                done.set()

    def update(self):
        self.store.set('antivirus_update_attempt', time.time())
        self.verify()
        self.database.mkdir(exist_ok=True)
        config = self.root / 'freshclam.conf'
        # FreshClam verifies official signed databases and respects its CDN cooldown.
        config.write_text('\n'.join([
            'DatabaseDirectory "' + str(self.database) + '"', 'DatabaseMirror database.clamav.net',
            'DNSDatabaseInfo current.cvd.clamav.net', 'Checks 4', 'ScriptedUpdates yes',
            'TestDatabases yes', 'ConnectTimeout 20', 'ReceiveTimeout 60', 'MaxAttempts 2',
        ]) + '\n', encoding='utf-8')
        tail = []
        def line(text):
            tail.append(text[:800])
            del tail[:-12]
            self.progress = {'phase': 'Updating official signatures', 'message': text[:250]}
        try:
            code = self._run([str(self.runtime / 'freshclam.exe'), '--config-file=' + str(config)], line)
            if code != 0 or not self.status()['definitionsReady']:
                message = f'ClamAV definitions update failed (exit {code}). ' + ' '.join(tail)[-1800:]
                self.store.set('antivirus_update_error', message)
                raise RuntimeError(message)
            self.store.set('antivirus_last_update', now())
            self.store.set('antivirus_update_error', None)
            return {'updated': True, 'version': VERSION}
        finally:
            self.progress = None

    def _snapshot(self, original):
        original = file_path(str(original))
        before = original.stat()
        if before.st_size > MAX_FILE:
            raise ValueError('The independent scanner limit is 256 MB per file.')
        target = self.staging / (uuid.uuid4().hex + '.scan')
        h = hashlib.sha256()
        count = 0
        try:
            with original.open('rb') as source, target.open('xb') as output:
                while block := source.read(1024 * 1024):
                    count += len(block)
                    if count > MAX_FILE:
                        raise ValueError('File exceeded the scan limit while being copied.')
                    output.write(block)
                    h.update(block)
            after = original.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError('File changed while its scan snapshot was being created.')
            return target, h.hexdigest()
        except Exception:
            target.unlink(missing_ok=True)
            raise

    def _args(self, target):
        return [str(self.runtime / 'clamscan.exe'), '--database=' + str(self.database), '--official-db-only=yes',
                '--stdout', '--infected', '--no-summary', '--max-filesize=256M', '--max-scansize=1024M',
                '--max-recursion=20', '--max-files=10000', '--alert-exceeds-max=yes',
                '--follow-dir-symlinks=0', '--follow-file-symlinks=0', str(target)]

    def scan_one(self, original):
        target, sha = self._snapshot(original)
        lines = []
        try:
            code = self._run(self._args(target), lambda s: lines.append(s[:1000]), cancellable=True)
            found = [line[len(str(target)) + 2:-6] for line in lines if line.startswith(str(target) + ': ') and line.endswith(' FOUND')]
            if code == 1 and found:
                sig = found[0]
                verdict = 'limited' if sig.startswith(('Heuristics.Limits.', 'Heuristics.Encrypted.')) else 'review' if sig.startswith(('Heuristics.', 'PUA.')) else 'infected'
            elif code == 0:
                sig, verdict = '', 'no_detection'
            else:
                sig, verdict = '', 'error'
            return {'path': str(original), 'sha256': sha, 'signature': sig, 'verdict': verdict, 'exitCode': code,
                    'detail': ' '.join(lines)[-1500:] if verdict == 'error' else ''}
        finally:
            target.unlink(missing_ok=True)

    def scan_batch(self, batch):
        """One database load for up to 1,024 private stable file snapshots."""
        listing = self.staging / (uuid.uuid4().hex + '.list')
        mapping = {os.path.normcase(str(item['snapshot'])): item for item in batch}
        results = {}
        listing.write_text('\n'.join(str(item['snapshot']) for item in batch) + '\n', encoding='utf-8')
        def line(text):
            prefix, _, value = text.partition(': ')
            key = os.path.normcase(prefix)
            if key not in mapping:
                return
            original = mapping[key]
            sig, verdict = '', 'error'
            if value in ('OK', 'Empty file'):
                verdict = 'no_detection'
            elif value.endswith(' FOUND'):
                sig = value[:-6]
                verdict = 'limited' if sig.startswith(('Heuristics.Limits.', 'Heuristics.Encrypted.')) else 'review' if sig.startswith(('Heuristics.', 'PUA.')) else 'infected'
            results[key] = {'path': original['path'], 'sha256': original['sha256'], 'signature': sig, 'verdict': verdict}
            if self.progress:
                self.progress['batchFinished'] = len(results)
        try:
            args = [a for a in self._args('')[:-1] if a != '--infected'] + ['--file-list=' + str(listing)]
            code = self._run(args, line, cancellable=True)
            output = [results.get(key, {'path': item['path'], 'sha256': item['sha256'], 'signature': '', 'verdict': 'error'}) for key, item in mapping.items()]
            # An infected exit without an attributable result cannot validate any
            # malware claim. The caller records the batch as incomplete.
            inconsistent = code == 1 and not any(x['verdict'] in ('infected', 'review', 'limited') for x in output)
            if code != 1:
                for item in output:
                    if item['verdict'] == 'infected':
                        item['verdict'] = 'review'
                        inconsistent = True
            return output, code not in (0, 1) or inconsistent
        finally:
            listing.unlink(missing_ok=True)
            for item in batch:
                item['snapshot'].unlink(missing_ok=True)

    def files(self, roots, counts):
        """Bounded enumeration; skips are explicit, never a clean-scan verdict."""
        seen = set()
        for root in roots:
            try:
                root = file_path(str(root), directory=True)
            except (ValueError, OSError):
                counts['skipped'] += 1
                continue
            stack = [root]
            while stack and not self.cancel.is_set():
                current = stack.pop()
                try:
                    info = current.lstat()
                    if getattr(info, 'st_file_attributes', 0) & SKIP_ATTRIBUTES or current.is_symlink() or current.is_relative_to(self.store.folder):
                        counts['skipped'] += 1
                        continue
                    if current.is_dir():
                        with os.scandir(current) as entries:
                            stack.extend(Path(e.path) for e in entries)
                        continue
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE or any(ord(c) < 32 for c in str(current)):
                        counts['skipped'] += 1
                        continue
                    key = str(current).casefold()
                    if key in seen:
                        continue
                    seen.add(key)
                    counts['enumerated'] += 1
                    if counts['enumerated'] > MAX_FILES:
                        counts['skipped'] += 1
                        counts['limitReached'] = True
                        return
                    yield current
                except (OSError, ValueError):
                    counts['skipped'] += 1

    def scan(self, job_id, roots):
        if not self.process_lock.acquire(blocking=False):
            raise ValueError('The independent scanner is already busy.')
        self.cancel.clear()
        self.active_scan = True
        counts = {'enumerated': 0, 'scanned': 0, 'skipped': 0, 'errors': 0, 'detected': 0, 'limitReached': False}
        started = time.monotonic()
        try:
            self.verify()
            if not self.status()['definitionsReady']:
                raise ValueError('Install and update the independent engine definitions before scanning.')
            findings, batch, batch_bytes = [], [], 0
            def flush():
                if not batch:
                    return
                self.progress = {'phase': 'Scanning with independent engine', **counts, 'batchFiles': len(batch), 'batchFinished': 0}
                items, had_error = self.scan_batch(batch)
                if had_error:
                    counts['errors'] += 1
                batch.clear()
                if self.cancel.is_set():
                    return
                for item in items:
                    if item['verdict'] == 'error':
                        counts['errors'] += 1
                        continue
                    counts['scanned'] += 1
                    if item['verdict'] != 'no_detection':
                        detection_id = uuid.uuid4().hex
                        with self.store.connect() as c:
                            c.execute('INSERT INTO detections VALUES(?,?,?,?,?,?,?,?)',
                                      (detection_id, job_id, now(), item['path'], item['signature'], item['sha256'], item['verdict'], 'open'))
                        counts['detected'] += 1
                        findings.append(item)
            try:
                for path in self.files(roots, counts):
                    if self.cancel.is_set():
                        break
                    self.progress = {'phase': 'Preparing stable scan snapshots', **counts, 'current': str(path)}
                    try:
                        snapshot, sha = self._snapshot(path)
                        batch.append({'path': str(path), 'sha256': sha, 'snapshot': snapshot})
                        batch_bytes += snapshot.stat().st_size
                        if len(batch) >= 1024 or batch_bytes >= 256 * 1024 * 1024:
                            flush()
                            batch_bytes = 0
                    except (OSError, ValueError):
                        counts['errors'] += 1
                if not self.cancel.is_set():
                    flush()
            finally:
                for item in batch:
                    item['snapshot'].unlink(missing_ok=True)
            result_state = classify_scan(1 if findings else 0, findings, counts['errors'], counts['skipped'], self.cancel.is_set())
            if counts['scanned'] == 0 and result_state == 'completed':
                result_state = 'partial'
            return {'status': result_state, **counts, 'seconds': round(time.monotonic() - started, 1),
                    'note': 'Official ClamAV signatures. Review detections and skipped/failed files separately. No pre-execution blocking.'}
        finally:
            self.active_scan = False
            self.progress = None
            self.process_lock.release()
