"""Build a source-only ZIP from an explicit allowlist; never package PC evidence."""
import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ['launch.py', 'Start Sentinel Local.cmd', 'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'VALIDATION.md', 'PRODUCT_PLAN.md']
PATTERNS = {'app': '*.py', 'tests': '*.py', 'web': '*', 'tools': '*.py'}


def source_files():
    files = [ROOT / name for name in FILES]
    for folder, pattern in PATTERNS.items():
        files.extend(path for path in (ROOT / folder).glob(pattern) if path.is_file() and path.suffix in {'.py', '.html', '.css', '.js'})
    return sorted(set(files))


def main():
    output = ROOT / 'dist'
    output.mkdir(exist_ok=True)
    target = output / 'Sentinel-Local-source.zip'
    files = source_files()
    checksums = '\n'.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.relative_to(ROOT).as_posix() for p in files) + '\n'
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, 'Sentinel-Local/' + path.relative_to(ROOT).as_posix())
        archive.writestr('Sentinel-Local/SHA256SUMS.txt', checksums)
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Source archive verification failed.')
    print(f'Created {target.name}: {len(files)} source files, {target.stat().st_size:,} bytes.')


if __name__ == '__main__':
    main()
