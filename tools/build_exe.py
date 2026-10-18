"""Build the Windows app: dist/SentinelLocal/SentinelLocal.exe, a portable ZIP and, if Inno Setup is installed, an installer.

Requires `pip install pyinstaller` (build machine only; the app itself stays stdlib-only).
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.search(r"^VERSION = '([^']+)'", (ROOT / 'app/server.py').read_text(encoding='utf-8'), re.M).group(1)
NUMERIC = '.'.join((re.findall(r'\d+', VERSION) + ['0'] * 4)[:4])
VERSION_INFO = f'''VSVersionInfo(
  ffi=FixedFileInfo(filevers=({NUMERIC.replace('.', ', ')}), prodvers=({NUMERIC.replace('.', ', ')})),
  kids=[StringFileInfo([StringTable('040904B0', [
    StringStruct('CompanyName', 'anshnt'), StringStruct('FileDescription', 'Sentinel Local antivirus and PC cleaner'),
    StringStruct('FileVersion', '{VERSION}'), StringStruct('InternalName', 'SentinelLocal'),
    StringStruct('OriginalFilename', 'SentinelLocal.exe'), StringStruct('ProductName', 'Sentinel Local'),
    StringStruct('ProductVersion', '{VERSION}'), StringStruct('LegalCopyright', 'anshnt')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])])
'''


def inno_compiler():
    for base in (os.environ.get('ProgramFiles(x86)'), os.environ.get('ProgramFiles'), os.environ.get('LOCALAPPDATA', '') + r'\Programs'):
        if base and (Path(base) / 'Inno Setup 6/ISCC.exe').is_file():
            return Path(base) / 'Inno Setup 6/ISCC.exe'
    return shutil.which('iscc')


def main():
    import PyInstaller.__main__
    build, dist = ROOT / 'build', ROOT / 'dist'
    build.mkdir(exist_ok=True)
    (build / 'version.txt').write_text(VERSION_INFO, encoding='utf-8')
    # One folder, not one-file: no self-extraction to Temp on every start, and
    # far fewer antivirus false positives than packed single-file executables.
    PyInstaller.__main__.run([
        str(ROOT / 'launch.py'), '--name', 'SentinelLocal', '--windowed', '--noconfirm', '--clean',
        '--icon', str(ROOT / 'assets/sentinel.ico'), '--version-file', str(build / 'version.txt'),
        '--add-data', f'{ROOT / "web"}{os.pathsep}web',
        '--distpath', str(dist), '--workpath', str(build / 'pyinstaller'), '--specpath', str(build)])
    app = dist / 'SentinelLocal'
    for name in ('README.md', 'SECURITY.md'):
        shutil.copy(ROOT / name, app / name)
    portable = shutil.make_archive(str(dist / f'SentinelLocal-{VERSION}-portable'), 'zip', dist, 'SentinelLocal')
    print('Built', app / 'SentinelLocal.exe', 'and', Path(portable).name)
    compiler = inno_compiler()
    if compiler:
        subprocess.run([str(compiler), f'/DAppVersion={VERSION}', str(ROOT / 'installer/SentinelLocal.iss')], check=True)
        print('Built', f'SentinelLocal-Setup-{VERSION}.exe')
    elif '--installer' in sys.argv:
        raise SystemExit('Inno Setup 6 (ISCC.exe) was not found.')
    else:
        print('Inno Setup not found; skipped the installer.')


if __name__ == '__main__':
    main()
