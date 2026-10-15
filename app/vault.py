"""Reversible Windows-user encrypted quarantine with source identity checks.

Only completed independent-engine signature detections can enter the vault.
Heuristic/review/limit results cannot authorize deletion of an original file.
"""
import ctypes
import hashlib
import hmac
import os
import re
import stat
import uuid
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path

from .core import file_path, now

MAX_VAULT = 64 * 1024 * 1024


class Blob(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]


def protect(data, decrypt=False):
    if os.name != 'nt':
        raise ValueError('Encrypted quarantine requires Windows DPAPI.')
    library = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    raw = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(raw, ctypes.POINTER(ctypes.c_ubyte)))
    output = Blob()
    fn = library.CryptUnprotectData if decrypt else library.CryptProtectData
    fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p if decrypt else wintypes.LPCWSTR,
                   ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    fn.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    description = None if decrypt else 'Sentinel Local quarantined file'
    if not fn(ctypes.byref(source), description, None, None, None, 1, ctypes.byref(output)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        kernel.LocalFree(output.data)


def permitted_source(path, app_data):
    path = file_path(str(path))
    protected = [app_data, Path(__file__).resolve().parents[1]]
    for key in ('SystemRoot', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramData'):
        if os.environ.get(key):
            protected.append(Path(os.environ[key]).resolve())
    if any(path.is_relative_to(root) for root in protected):
        raise ValueError('Quarantine of Windows, installed program, application or engine data files is blocked. Review this detection manually.')
    if path.stat().st_size > MAX_VAULT:
        raise ValueError('Encrypted quarantine supports files up to 64 MB. Review larger detections manually.')
    return path


@contextmanager
def locked_source(path, app_data):
    """Lock and delete the verified handle, never a potentially replaced pathname."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.ReadFile.restype = wintypes.BOOL
    class FileInfo(ctypes.Structure):
        _fields_ = [('attributes', wintypes.DWORD), ('created', wintypes.FILETIME), ('accessed', wintypes.FILETIME),
                    ('written', wintypes.FILETIME), ('volume', wintypes.DWORD), ('sizeHigh', wintypes.DWORD),
                    ('sizeLow', wintypes.DWORD), ('links', wintypes.DWORD), ('indexHigh', wintypes.DWORD), ('indexLow', wintypes.DWORD)]
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInfo)]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    # GENERIC_READ | DELETE, exclusive sharing, OPEN_EXISTING, OPEN_REPARSE_POINT.
    handle = kernel.CreateFileW(str(path), 0x80010000, 0, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = FileInfo()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.attributes & (0x400 | 0x1000 | 0x40000 | 0x400000) or info.links != 1:
            raise ValueError('Quarantine of links, cloud placeholders or offline files is blocked.')
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            raise ValueError('Could not verify the locked file identity.')
        resolved = buffer.value.removeprefix('\\\\?\\')
        if resolved.casefold() != str(path).casefold():
            raise ValueError('File path changed during quarantine. No original was removed.')
        # Path policy was validated before opening. The final handle path must
        # match it; share=0 prevents writers/replacements until the handle closes.
        chunks, total = [], 0
        while True:
            block = ctypes.create_string_buffer(1024 * 1024)
            read = wintypes.DWORD()
            if not kernel.ReadFile(handle, block, len(block), ctypes.byref(read), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if not read.value:
                break
            total += read.value
            if total > MAX_VAULT:
                raise ValueError('Locked file exceeds the encrypted quarantine limit.')
            chunks.append(block.raw[:read.value])
        def remove_locked_file():
            delete = ctypes.c_ubyte(1)
            if not kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(delete), ctypes.sizeof(delete)):
                raise ctypes.WinError(ctypes.get_last_error())
        yield b''.join(chunks), remove_locked_file
    finally:
        kernel.CloseHandle(handle)


class Vault:
    def __init__(self, store):
        self.store = store
        self.folder = store.folder / 'quarantine'
        self.recovery = store.folder / 'recovered'
        self.folder.mkdir(exist_ok=True)
        self.recovery.mkdir(exist_ok=True)
        with self.store.connect() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS vault_checks(id TEXT PRIMARY KEY, checked TEXT, detail TEXT);
            CREATE TABLE IF NOT EXISTS recovery_attempts(id TEXT PRIMARY KEY, vault TEXT, time TEXT, path TEXT, status TEXT, detail TEXT);
            ''')

    @staticmethod
    def _regular(path, limit):
        # Never follow a replaced vault/recovery file or a cloud placeholder.
        for component in [*reversed(path.parents), path]:
            info = component.lstat()
            if getattr(info, 'st_file_attributes', 0) & (0x400 | 0x1000 | 0x40000 | 0x400000) or component.is_symlink():
                raise ValueError('Vault links, cloud placeholders and offline files are blocked.')
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError('Vault item is not a supported regular file or exceeds its limit.')

    def _content(self, entry):
        encrypted = self.folder / (entry['id'] + '.dpapi')
        self._regular(encrypted, MAX_VAULT + 1024 * 1024)
        content = protect(encrypted.read_bytes(), decrypt=True)
        if len(content) > MAX_VAULT or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), entry['sha256']):
            raise ValueError('Vault integrity verification failed; recovery blocked.')
        return content

    def _check(self, item_id, detail):
        with self.store.connect() as c:
            c.execute('INSERT OR REPLACE INTO vault_checks VALUES(?,?,?)', (item_id, now(), detail))

    def reconcile(self):
        """Single-instance startup audit. Never retry deletion or open a sample."""
        rows = self.store.rows("SELECT * FROM vault WHERE status IN ('prepared','removal_unverified','recovering','recovery_incomplete','recovery_blocked')")
        for entry in rows:
            try:
                self._content(entry)
            except (ValueError, OSError) as exc:
                state, detail = 'recovery_blocked', 'Encrypted recovery copy could not be verified: ' + str(exc)
            else:
                state = 'removal_unverified'
                detail = 'Encrypted copy verified after restart. Original removal is unverified; no original was touched.'
                if entry['status'] in ('recovering', 'recovery_incomplete'):
                    state = 'recovery_incomplete'
                    detail = 'Recovery was interrupted. Existing output was preserved; retry writes a new separate copy.'
                    destination = Path(entry['recovery'] or '')
                    attempts = self.store.rows('SELECT id FROM recovery_attempts WHERE vault=? AND path=?', (entry['id'], str(destination)))
                    try:
                        if not attempts or destination.parent != self.recovery or not re.fullmatch(r'[a-f0-9]{32}-.+\.restored', destination.name):
                            raise ValueError('Recovery destination is not an owned attempt.')
                        self._regular(destination, MAX_VAULT)
                        if not hmac.compare_digest(hashlib.sha256(destination.read_bytes()).hexdigest(), entry['sha256']):
                            raise ValueError('Recovery copy is incomplete or changed.')
                    except (ValueError, OSError):
                        with self.store.connect() as c:
                            c.execute("UPDATE recovery_attempts SET status='incomplete',detail=? WHERE vault=? AND path=?", (detail, entry['id'], str(destination)))
                    else:
                        state, detail = 'recovered', 'Interrupted recovery completed: saved copy SHA-256 verified after restart.'
                        with self.store.connect() as c:
                            c.execute("UPDATE recovery_attempts SET status='verified',detail=? WHERE vault=? AND path=?", (detail, entry['id'], str(destination)))
            with self.store.connect() as c:
                c.execute('UPDATE vault SET status=? WHERE id=?', (state, entry['id']))
                c.execute("UPDATE detections SET status=? WHERE id=?", ('quarantined' if state == 'recovered' else state, entry['detection']))
            self._check(entry['id'], detail)
            self.store.log('Vault restart audit', detail, 'review')
        return len(rows)

    def quarantine(self, detection_id):
        if not isinstance(detection_id, str) or not re.fullmatch('[a-f0-9]{32}', detection_id):
            raise ValueError('Choose an independent-engine detection.')
        rows = self.store.rows('SELECT * FROM detections WHERE id=?', (detection_id,))
        if not rows or rows[0]['verdict'] != 'infected' or rows[0]['status'] != 'open':
            raise ValueError('Only open signature detections can be quarantined. Review indicators cannot remove files.')
        detection = rows[0]
        path = permitted_source(detection['path'], self.store.folder)
        vault_id = uuid.uuid4().hex
        target = self.folder / (vault_id + '.dpapi')
        prepared = False
        try:
            with locked_source(path, self.store.folder) as (content, remove):
                actual = hashlib.sha256(content).hexdigest()
                if not hmac.compare_digest(actual, detection['sha256']):
                    raise ValueError('The original file changed since detection. Rescan it; quarantine was blocked.')
                encrypted = protect(content)
                with target.open('xb') as output:
                    output.write(encrypted)
                    output.flush()
                    os.fsync(output.fileno())
                recovered_hash = hashlib.sha256(protect(target.read_bytes(), decrypt=True)).hexdigest()
                if not hmac.compare_digest(recovered_hash, actual):
                    raise ValueError('Encrypted copy recovery verification failed. The original was preserved.')
                with self.store.connect() as c:
                    c.execute('INSERT INTO vault VALUES(?,?,?,?,?,?,?,?)',
                              (vault_id, detection_id, now(), str(path), actual, len(content), 'prepared', None))
                prepared = True
                # Encrypted copy and durable metadata exist before removal.
                remove()
            with self.store.connect() as c:
                c.execute("UPDATE vault SET status='quarantined' WHERE id=?", (vault_id,))
                c.execute("UPDATE detections SET status='quarantined' WHERE id=?", (detection_id,))
            self.store.log('File quarantined', str(path) + ' — protected with Windows user encryption.', 'review')
            return vault_id
        except Exception:
            if prepared:
                with self.store.connect() as c:
                    c.execute("UPDATE vault SET status='removal_unverified' WHERE id=?", (vault_id,))
                    c.execute("UPDATE detections SET status='removal_unverified' WHERE id=?", (detection_id,))
            elif target.is_file():
                target.unlink()
            raise

    def recover(self, vault_id):
        if not isinstance(vault_id, str) or not re.fullmatch('[a-f0-9]{32}', vault_id):
            raise ValueError('Choose a quarantined item.')
        rows = self.store.rows('SELECT * FROM vault WHERE id=?', (vault_id,))
        if not rows or rows[0]['status'] not in ('quarantined', 'removal_unverified', 'prepared', 'recovery_incomplete', 'recovery_blocked'):
            raise ValueError('This vault entry cannot be recovered again.')
        entry = rows[0]
        content = self._content(entry)
        # Never overwrite an original or silently put a detected executable back
        # into circulation. The user must review/rename this recovered copy.
        # Bound the output component even when the original is a long NTFS name.
        # The ledger retains the complete original path and content hash.
        display_name = Path(entry['path']).name[:100]
        attempt = uuid.uuid4().hex
        destination = self.recovery / (attempt + '-' + display_name + '.restored')
        # Persist intent first. A crash after writing cannot strand an
        # unrecorded output or force an overwrite on the next recovery attempt.
        with self.store.connect() as c:
            c.execute('INSERT INTO recovery_attempts VALUES(?,?,?,?,?,?)', (attempt, vault_id, now(), str(destination), 'writing', 'Recovery intent saved.'))
            c.execute("UPDATE vault SET status='recovering',recovery=? WHERE id=?", (str(destination), vault_id))
        try:
            with destination.open('x+b') as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
                output.seek(0)
                if not hmac.compare_digest(hashlib.sha256(output.read()).hexdigest(), entry['sha256']):
                    raise ValueError('Recovered copy verification failed.')
            with self.store.connect() as c:
                c.execute("UPDATE vault SET status='recovered' WHERE id=?", (vault_id,))
                c.execute("UPDATE recovery_attempts SET status='verified',detail='Written, flushed and SHA-256 verified.' WHERE id=?", (attempt,))
        except Exception:
            with self.store.connect() as c:
                c.execute("UPDATE vault SET status='recovery_incomplete' WHERE id=?", (vault_id,))
                c.execute("UPDATE recovery_attempts SET status='incomplete',detail='Output preserved; retry writes a new copy.' WHERE id=?", (attempt,))
            raise
        self.store.log('Quarantine copy recovered', str(destination) + ' — review before opening; original location was not overwritten.', 'review')
        return str(destination)
