"""Double-click launcher. No installation, UAC prompt or public listener."""
import json
import hashlib
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from app.core import DATA


def mutex_name():
    # Different users in one Windows session must not block each other's console.
    user_key = hashlib.sha256(str(Path.home()).casefold().encode('utf-8')).hexdigest()[:16]
    return 'Local\\SentinelLocal.Console.v1.' + user_key


def instance():
    try:
        value = json.loads((DATA / 'instance.json').read_text(encoding='utf-8'))
        port = int(value['port'])
        if not 1024 <= port <= 65535:
            return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f'http://127.0.0.1:{port}/health', timeout=1) as response:
            health = json.load(response)
        if health.get('app') == 'Sentinel Local' and health.get('pid') == value['pid']:
            return value
    except (OSError, ValueError, KeyError):
        pass
    return None


def main():
    if os.name != 'nt' or sys.version_info < (3, 11):
        raise SystemExit('Sentinel Local requires Windows and Python 3.11 or newer.')
    if '--serve' in sys.argv:
        # One server per local user. The Windows mutex is released on process exit.
        import ctypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        kernel.CreateMutexW.restype = ctypes.c_void_p
        handle = kernel.CreateMutexW(None, False, mutex_name())
        if not handle or ctypes.get_last_error() == 183:
            return
        # Fixed name so the installer can ask to close the app before replacing files.
        running = kernel.CreateMutexW(None, False, 'SentinelLocal.Running')
        from app.server import serve
        serve()
        return
    current = instance()
    if current is None:
        DATA.mkdir(parents=True, exist_ok=True)
        from app.core import file_path
        from app.windows import secure_data_folder
        file_path(str(DATA), directory=True)
        secure_data_folder(DATA)
        from app.startup import launch_args
        # Detached user process: scans do not depend on a transient terminal session.
        with (DATA / 'runtime-errors.log').open('ab') as errors:
            subprocess.Popen(launch_args('--serve'), cwd=ROOT,
                             stdin=subprocess.DEVNULL, stdout=errors, stderr=errors,
                             creationflags=getattr(subprocess, 'DETACHED_PROCESS', 0) | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0),
                             close_fds=True, shell=False)
        for _ in range(80):
            time.sleep(0.25)
            current = instance()
            if current:
                break
    if not current:
        raise RuntimeError(f'The local service did not start. Check {DATA / "runtime-errors.log"}.')
    if '--no-browser' not in sys.argv:
        os.startfile(f'http://127.0.0.1:{current["port"]}/open/{current["nonce"]}')
    print('Sentinel Local is running on this PC. Use the launcher to reopen its private session.')


if __name__ == '__main__':
    if getattr(sys, 'frozen', False) and '--serve' not in sys.argv:
        # The packaged app has no console: show launch failures in a dialog.
        try:
            main()
        except Exception as exc:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, str(exc), 'Sentinel Local', 0x10)
            sys.exit(1)
    else:
        main()
