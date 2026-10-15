"""Reversible Windows-user encrypted quarantine with source identity checks.

Only completed independent-engine signature detections can enter the vault.
Heuristic/review/limit results cannot authorize deletion of an original file.
"""
import ctypes
import hashlib
import hmac
import os
import re
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
            elif target.is_file():
                target.unlink()
            raise

    def recover(self, vault_id):
        if not isinstance(vault_id, str) or not re.fullmatch('[a-f0-9]{32}', vault_id):
            raise ValueError('Choose a quarantined item.')
        rows = self.store.rows('SELECT * FROM vault WHERE id=?', (vault_id,))
        if not rows or rows[0]['status'] not in ('quarantined', 'removal_unverified', 'prepared'):
            raise ValueError('This vault entry cannot be recovered again.')
        entry = rows[0]
        encrypted = self.folder / (vault_id + '.dpapi')
        if encrypted.stat().st_size > MAX_VAULT + 1024 * 1024:
            raise ValueError('Vault item exceeds the recovery limit.')
        content = protect(encrypted.read_bytes(), decrypt=True)
        if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), entry['sha256']):
            raise ValueError('Vault integrity verification failed; recovery blocked.')
        # Never overwrite an original or silently put a detected executable back
        # into circulation. The user must review/rename this recovered copy.
        destination = self.recovery / (vault_id + '-' + Path(entry['path']).name + '.restored')
        with destination.open('xb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        with self.store.connect() as c:
            c.execute("UPDATE vault SET status='recovered',recovery=? WHERE id=?", (str(destination), vault_id))
        self.store.log('Quarantine copy recovered', str(destination) + ' — review before opening; original location was not overwritten.', 'review')
        return str(destination)
