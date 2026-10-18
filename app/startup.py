"""Optional current-user sign-in launch; never installs an elevated service."""
import os
import subprocess
import sys
from pathlib import Path

from .core import ROOT

NAME = 'Sentinel Local Antivirus'
KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'


def launch_args(*args):
    """Command that runs the launcher: the packaged exe itself, or windowless Python with launch.py."""
    if getattr(sys, 'frozen', False):
        return [sys.executable, *args]
    executable = Path(sys.executable)
    windowless = executable.with_name('pythonw.exe')
    return [str(windowless if windowless.exists() else executable), str(ROOT / 'launch.py'), *args]


def command():
    return subprocess.list2cmdline(launch_args('--no-browser'))


def current():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY) as key:
            value, _ = winreg.QueryValueEx(key, NAME)
            return value
    except FileNotFoundError:
        return None


def status():
    try:
        value = current()
        return {'available': True, 'enabled': value == command(), 'entryExists': value is not None}
    except OSError:
        return {'available': False, 'enabled': None, 'entryExists': None}


def configure(enabled, store):
    import winreg
    if not isinstance(enabled, bool):
        raise ValueError('Choose whether to launch Sentinel at Windows sign-in.')
    expected, previous = command(), current()
    if previous is not None and previous not in (expected, store.get('startup_command')):
        raise ValueError('A different application owns this startup value. Review Windows Startup Apps before changing it.')
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, NAME, 0, winreg.REG_SZ, expected)
        elif previous is not None:
            winreg.DeleteValue(key, NAME)
    store.set('startup_command', expected if enabled else None)
    store.log('Windows sign-in launch ' + ('enabled' if enabled else 'disabled'), 'Current-user launch only. Defender remains independent.')
