"""PC Cleaner: junk files, Recycle Bin, large/old files, installed programs and startup apps.

Every destructive action is limited to what this module found itself: junk
cleaning only touches fixed cache/temp folders, review files must come from the
last scan and go to the Recycle Bin, and uninstallers come from the Windows
registry, never from a web request.
"""
import ctypes
import fnmatch
import hashlib
import os
import re
import stat
import struct
import threading
import time
from pathlib import Path

from .core import file_path, now

SKIP_ATTRIBUTES = 0x400 | 0x1000 | 0x40000 | 0x400000  # reparse, offline, cloud recall
JUNK_AGE = 24 * 3600  # files touched in the last day may still be in use
OLD_DOWNLOAD_AGE = 30 * 24 * 3600
LARGE_FILE = 100 * 1024 * 1024
MAX_ENTRIES = 500000
MAX_REVIEW = 100
INSTALLER_SUFFIXES = {'.exe', '.msi', '.msix', '.iso', '.zip', '.7z', '.rar'}
UNINSTALL = r'Software\Microsoft\Windows\CurrentVersion\Uninstall'
RUN = r'Software\Microsoft\Windows\CurrentVersion\Run'
RUN32 = r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
APPROVED = r'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
SETTINGS_PAGES = {'apps': 'ms-settings:appsfeatures', 'storage': 'ms-settings:storagesense'}


def _env(name, default):
    return Path(os.environ.get(name) or default)


def junk_categories():
    local = _env('LOCALAPPDATA', Path.home() / 'AppData/Local')
    windows = _env('SystemRoot', r'C:\Windows')
    program_data = _env('ProgramData', r'C:\ProgramData')
    browsers = []
    for vendor in ('Google/Chrome', 'Microsoft/Edge', 'BraveSoftware/Brave-Browser', 'Vivaldi'):
        data = local / vendor / 'User Data'
        browsers += [data / 'ShaderCache', data / 'GrShaderCache']
        for profile in [data / 'Default', *data.glob('Profile *')]:
            browsers += [profile / 'Cache', profile / 'Code Cache', profile / 'GPUCache']
    browsers += [p / 'cache2' for p in (local / 'Mozilla/Firefox/Profiles').glob('*')]
    return {
        'temp': ('Your temporary files', 'Leftovers from installers and apps in your Temp folder.', [_env('TEMP', local / 'Temp')], None),
        'windows-temp': ('Windows temporary files', 'System Temp folder. Some files need administrator access.', [windows / 'Temp'], None),
        'browser': ('Browser caches', 'Chrome, Edge, Brave, Vivaldi and Firefox caches. Logins, history and bookmarks are kept.', browsers, None),
        'thumbnails': ('Thumbnail cache', 'File Explorer rebuilds thumbnails when needed.', [local / 'Microsoft/Windows/Explorer'], 'thumbcache_*.db'),
        'crash': ('Crash dumps & error reports', 'Old crash dumps and Windows Error Reporting files.', [local / 'CrashDumps', local / 'Microsoft/Windows/WER', program_data / 'Microsoft/Windows/WER'], None),
    }


def _attributes(info):
    return getattr(info, 'st_file_attributes', 0)


def walk(root, pattern=None, older_than=None, folders=None):
    """Yield (path, size, mtime) for regular files under root.

    Never enters symlinks, junctions or cloud placeholders: a junction in a temp
    folder must not turn junk cleaning into deleting a user's documents.
    """
    try:
        info = os.lstat(root)
    except OSError:
        return
    if not stat.S_ISDIR(info.st_mode) or _attributes(info) & SKIP_ATTRIBUTES:
        return
    stack, seen = [str(root)], 0
    while stack:
        folder = stack.pop()
        try:
            with os.scandir(folder) as entries:
                entries = list(entries)
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > MAX_ENTRIES:
                return
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if _attributes(info) & SKIP_ATTRIBUTES or stat.S_ISLNK(info.st_mode):
                continue
            if stat.S_ISDIR(info.st_mode):
                stack.append(entry.path)
                if folders is not None:
                    folders.append((entry.path, info.st_mtime))
            elif stat.S_ISREG(info.st_mode) and (pattern is None or fnmatch.fnmatch(entry.name.lower(), pattern)) \
                    and (older_than is None or info.st_mtime < older_than):
                yield entry.path, info.st_size, info.st_mtime


def clean_roots(roots, pattern=None, older_than=None):
    freed = removed = failed = 0
    for root in roots:
        folders = []
        for path, size, _ in walk(root, pattern, older_than, folders):
            try:
                os.chmod(path, stat.S_IWRITE)
                os.remove(path)
                freed += size
                removed += 1
            except OSError:
                failed += 1  # locked by a running app; left in place
        # Deepest first. rmdir only removes empty folders, and recently changed
        # ones may be about to be used by an app.
        for folder, mtime in sorted(folders, key=lambda f: -len(f[0])):
            if older_than is None or mtime < older_than:
                try:
                    os.rmdir(folder)
                except OSError:
                    pass
    return {'freed': freed, 'removed': removed, 'failed': failed}


class SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [('cbSize', ctypes.c_uint32), ('i64Size', ctypes.c_int64), ('i64NumItems', ctypes.c_int64)]


class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [('hwnd', ctypes.c_void_p), ('wFunc', ctypes.c_uint), ('pFrom', ctypes.c_wchar_p), ('pTo', ctypes.c_wchar_p),
                ('fFlags', ctypes.c_ushort), ('fAnyOperationsAborted', ctypes.c_int), ('hNameMappings', ctypes.c_void_p),
                ('lpszProgressTitle', ctypes.c_wchar_p)]


def recycle_bin():
    info = SHQUERYRBINFO(ctypes.sizeof(SHQUERYRBINFO), 0, 0)
    if ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info)):
        return None
    return {'bytes': info.i64Size, 'items': info.i64NumItems}


def empty_recycle_bin():
    # No confirmation, progress or sound: the user already confirmed in the app.
    # E_UNEXPECTED is returned when the bin is already empty.
    result = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x7) & 0xFFFFFFFF
    if result not in (0, 0x8000FFFF):
        raise OSError('Windows could not empty the Recycle Bin.')


def send_to_recycle_bin(path):
    # FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOF_WANTNUKEWARNING:
    # a file too large for the bin prompts instead of being silently destroyed.
    op = SHFILEOPSTRUCTW(None, 3, str(path) + '\0', None, 0x40 | 0x10 | 0x4 | 0x400 | 0x4000, 0, None, None)
    if ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op)) or op.fAnyOperationsAborted or Path(path).exists():
        raise OSError('Windows did not move this file to the Recycle Bin.')


def split_command(command):
    """Split a registry UninstallString into (executable, arguments)."""
    command = os.path.expandvars(command.strip())
    if command.startswith('"'):
        exe, _, args = command[1:].partition('"')
    else:
        match = re.match(r'(?i)^(.+?\.exe)(?=\s|$)(.*)$', command)
        if not match:
            raise ValueError('This program has no runnable uninstaller. Use Windows Installed apps instead.')
        exe, args = match.groups()
    exe, args = exe.strip(), args.strip()
    system32 = _env('SystemRoot', r'C:\Windows') / 'System32'
    if exe.lower() in ('msiexec', 'msiexec.exe') or Path(exe).name.lower() == 'msiexec.exe':
        exe = str(system32 / 'msiexec.exe')
        # Many MSI entries register the repair/modify command; /X is uninstall.
        args = re.sub(r'(?i)(^|\s)/I(?=\s*\{)', r'\1/X', args)
    elif not Path(exe).is_absolute():
        exe = str(system32 / exe)
    if not Path(exe).is_file():
        raise ValueError('The uninstaller registered for this program is missing. Use Windows Installed apps instead.')
    return exe, args


def _value(key, name):
    import winreg
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def installed_programs():
    import winreg
    sources = [('HKLM', winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY), ('HKLM32', winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
               ('HKCU', winreg.HKEY_CURRENT_USER, 0)]
    programs = {}
    for label, hive, view in sources:
        try:
            root = winreg.OpenKey(hive, UNINSTALL, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        with root:
            for index in range(winreg.QueryInfoKey(root)[0]):
                try:
                    name = winreg.EnumKey(root, index)
                    with winreg.OpenKey(root, name) as key:
                        title = _value(key, 'DisplayName')
                        if not title or _value(key, 'SystemComponent') == 1 or _value(key, 'ParentKeyName') \
                                or _value(key, 'ReleaseType') in ('Update', 'Hotfix', 'Security Update'):
                            continue
                        command = _value(key, 'UninstallString')
                        size = _value(key, 'EstimatedSize')
                        date = str(_value(key, 'InstallDate') or '')
                        item_id = hashlib.sha256(f'{label}\\{name}'.encode('utf-8')).hexdigest()[:20]
                        programs[item_id] = {
                            'id': item_id, 'name': str(title).strip(), 'publisher': _value(key, 'Publisher') or '',
                            'version': str(_value(key, 'DisplayVersion') or ''),
                            'installed': f'{date[:4]}-{date[4:6]}-{date[6:8]}' if re.fullmatch(r'\d{8}', date) else '',
                            'bytes': size * 1024 if isinstance(size, int) else None,
                            'scope': 'This user' if label == 'HKCU' else 'All users',
                            'command': str(command) if command else None}
                except OSError:
                    continue
    return sorted(programs.values(), key=lambda p: p['name'].lower())


def _startup_sources():
    import winreg
    user_folder = _env('APPDATA', Path.home() / 'AppData/Roaming') / r'Microsoft\Windows\Start Menu\Programs\Startup'
    common_folder = _env('ProgramData', r'C:\ProgramData') / r'Microsoft\Windows\Start Menu\Programs\StartUp'
    hkcu, hklm = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE
    # (label, registry hive, Run key or None for a folder, folder, StartupApproved subkey)
    return [('Current user', hkcu, RUN, None, 'Run'), ('All users', hklm, RUN, None, 'Run'), ('All users (32-bit)', hklm, RUN32, None, 'Run32'),
            ('Current user startup folder', hkcu, None, user_folder, 'StartupFolder'),
            ('All users startup folder', hklm, None, common_folder, 'StartupFolder')]


def startup_apps():
    import winreg
    items = []
    for label, hive, run, folder, approved in _startup_sources():
        names = []
        if run:
            try:
                with winreg.OpenKey(hive, run, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    for index in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, index)
                        names.append((name, str(value)))
            except OSError:
                continue
        elif folder.is_dir():
            names = [(p.name, str(p)) for p in folder.iterdir() if p.is_file() and p.name.lower() != 'desktop.ini']
        state = {}
        try:
            with winreg.OpenKey(hive, APPROVED + '\\' + approved, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                for index in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, index)
                    state[name] = value
        except OSError:
            pass
        for name, command in names:
            flag = state.get(name)
            item_id = hashlib.sha256(f'{label}\\{name}'.encode('utf-8')).hexdigest()[:20]
            items.append({'id': item_id, 'name': name, 'location': label, 'command': command,
                          'enabled': not (isinstance(flag, bytes) and flag[:1] and flag[0] & 1),
                          'needsAdmin': hive == winreg.HKEY_LOCAL_MACHINE})
    return items


def set_startup(item_id, enabled):
    """Enable/disable like Task Manager: the original entry is never deleted."""
    import winreg
    item = next((i for i in startup_apps() if i['id'] == item_id), None)
    if item is None:
        raise ValueError('That startup entry is no longer present. Refresh the list.')
    hive, approved = next((h, a) for label, h, _, _, a in _startup_sources() if label == item['location'])
    stamp = struct.pack('<Q', int((time.time() + 11644473600) * 10**7))  # FILETIME of the change
    value = b'\x02' + b'\x00' * 11 if enabled else b'\x03\x00\x00\x00' + stamp
    try:
        with winreg.CreateKeyEx(hive, APPROVED + '\\' + approved, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.SetValueEx(key, item['name'], 0, winreg.REG_BINARY, value)
    except PermissionError:
        raise ValueError('This startup entry is for all users. Run Sentinel as administrator or use Task Manager > Startup apps.')
    return item['name']


class Cleaner:
    def __init__(self, store):
        self.store = store
        self.lock = threading.Lock()
        self.busy = None
        self.progress = None
        self.junk = None
        self.bin = None
        self.review = []
        self.analyzed = None
        self.last = store.get('cleaner_last')
        self.error = None

    def status(self):
        return {'busy': self.busy, 'progress': self.progress, 'junk': self.junk, 'recycleBin': self.bin, 'review': self.review,
                'analyzed': self.analyzed, 'last': self.last, 'error': self.error,
                'programs': self.inventory('programs', installed_programs),
                'startup': self.inventory('startup', startup_apps)}

    def inventory(self, name, reader):
        # Registry reads are cheap but run on every poll; cache them briefly.
        cached = getattr(self, '_' + name, None)
        if cached is None or time.time() - cached[0] > 30:
            try:
                cached = (time.time(), reader())
            except OSError:
                cached = (time.time(), [])
            setattr(self, '_' + name, cached)
        return cached[1]

    def forget_inventory(self):
        self._programs = self._startup = None

    def start(self, name, work):
        with self.lock:
            if self.busy:
                raise ValueError('The cleaner is already working. Wait for it to finish.')
            self.busy = name
        self.error = None

        def run():
            try:
                work()
            except Exception as exc:
                self.error = str(exc)
                self.store.log('PC Cleaner: ' + name + ' failed', str(exc), 'review')
            finally:
                self.busy = self.progress = None
        threading.Thread(target=run, daemon=True).start()

    def analyze(self):
        self.start('analyze', self._analyze)

    def _analyze(self):
        cutoff = time.time() - JUNK_AGE
        junk = []
        for key, (title, detail, roots, pattern) in junk_categories().items():
            self.progress = 'Measuring ' + title.lower()
            files = size = 0
            for _, length, _ in (item for root in roots for item in walk(root, pattern, cutoff)):
                files += 1
                size += length
            junk.append({'id': key, 'title': title, 'detail': detail, 'files': files, 'bytes': size})
        self.junk = junk
        self.bin = recycle_bin() if os.name == 'nt' else None
        self.progress = 'Looking for large and old files'
        self.review = self._review_files()
        self.analyzed = now()
        self.forget_inventory()
        total = sum(c['bytes'] for c in junk) + (self.bin or {}).get('bytes', 0)
        self.store.log('PC Cleaner analysis finished', f'{total / 1048576:.1f} MB of junk found. Nothing was deleted.')

    def _review_files(self):
        home, found = Path.home(), {}
        downloads = home / 'Downloads'
        old = time.time() - OLD_DOWNLOAD_AGE
        for name in ('Downloads', 'Desktop', 'Documents', 'Videos', 'Pictures', 'Music'):
            for path, size, mtime in walk(home / name):
                reason = 'Large file' if size >= LARGE_FILE else None
                if reason is None and Path(path).suffix.lower() in INSTALLER_SUFFIXES and mtime < old and Path(path).is_relative_to(downloads):
                    reason = 'Old installer or archive in Downloads'
                if reason:
                    found[path] = {'path': path, 'bytes': size, 'modified': mtime, 'reason': reason}
        return sorted(found.values(), key=lambda f: -f['bytes'])[:MAX_REVIEW]

    def clean(self, categories, recycle_bin_too=False):
        known = junk_categories()
        if not isinstance(categories, list) or len(categories) > len(known) or any(c not in known for c in categories) \
                or not isinstance(recycle_bin_too, bool) or not (categories or recycle_bin_too):
            raise ValueError('Choose at least one junk category to clean.')
        self.start('clean', lambda: self._clean(categories, recycle_bin_too))

    def _clean(self, categories, recycle_bin_too):
        cutoff = time.time() - JUNK_AGE
        known, totals = junk_categories(), {'freed': 0, 'removed': 0, 'failed': 0}
        for key in categories:
            title, _, roots, pattern = known[key]
            self.progress = 'Cleaning ' + title.lower()
            for k, v in clean_roots(roots, pattern, cutoff).items():
                totals[k] += v
        if recycle_bin_too:
            before = recycle_bin() or {'bytes': 0, 'items': 0}
            empty_recycle_bin()
            totals['freed'] += before['bytes']
            totals['removed'] += before['items']
        self.last = {'time': now(), **totals}
        self.store.set('cleaner_last', self.last)
        self.store.log('PC Cleaner freed space', f"{totals['freed'] / 1048576:.1f} MB freed from {totals['removed']} items. "
                       f"{totals['failed']} in-use files were left in place.")
        self._analyze()

    def recycle(self, paths):
        allowed = {f['path'] for f in self.review}
        if not isinstance(paths, list) or not paths or len(paths) > MAX_REVIEW or any(p not in allowed for p in paths):
            raise ValueError('Choose files from the latest Large & old files list.')
        moved, failed = [], []
        for raw in paths:
            try:
                path = file_path(raw)
                send_to_recycle_bin(path)
                moved.append(raw)
            except (OSError, ValueError):
                failed.append(raw)
        self.review = [f for f in self.review if f['path'] not in moved]
        self.store.log('Files moved to the Recycle Bin', f'{len(moved)} moved, {len(failed)} could not be moved. Restore them from the Recycle Bin if needed.')
        return {'moved': len(moved), 'failed': failed}

    def uninstall(self, item_id):
        program = next((p for p in installed_programs() if p['id'] == item_id), None)
        if program is None:
            raise ValueError('That program is no longer installed. Refresh the list.')
        if not program['command']:
            raise ValueError('This program has no registered uninstaller. Use Windows Installed apps instead.')
        exe, args = split_command(program['command'])
        # ShellExecute lets the vendor's uninstaller show its own UAC prompt and UI.
        os.startfile(exe, 'open', args)
        self.forget_inventory()
        self.store.log('Uninstaller opened', program['name'] + ': follow its prompts to finish.')
        return program['name']

    def startup(self, item_id, enabled):
        if not isinstance(enabled, bool):
            raise ValueError('Choose whether this app starts with Windows.')
        name = set_startup(item_id, enabled)
        self.forget_inventory()
        self.store.log('Startup app ' + ('enabled' if enabled else 'disabled'), name + ': takes effect at next sign-in.')
        return name


def open_settings(page):
    if page not in SETTINGS_PAGES:
        raise ValueError('Unknown Windows settings page.')
    os.startfile(SETTINGS_PAGES[page])
