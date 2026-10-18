"""Start the built exe against a throwaway data folder and check it serves the app, then stop it."""
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'dist/SentinelLocal/SentinelLocal.exe'


def get(port, path, cookie=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    connection.request('GET', path, headers={'Cookie': cookie} if cookie else {})
    response = connection.getresponse()
    return response.status, dict(response.getheaders()), response.read()


def main():
    with tempfile.TemporaryDirectory() as data:
        env = dict(os.environ, LOCALAPPDATA=data)
        subprocess.run([str(EXE), '--no-browser'], env=env, check=True, timeout=60)
        instance = json.loads((Path(data) / 'SentinelLocal/instance.json').read_text(encoding='utf-8'))
        port = instance['port']
        try:
            status, _, body = get(port, '/health')
            assert status == 200 and json.loads(body)['app'] == 'Sentinel Local', body
            status, headers, _ = get(port, '/open/' + instance['nonce'])
            assert status == 303, status
            cookie = headers['Set-Cookie'].split(';')[0]
            status, _, page = get(port, '/', cookie)
            assert status == 200 and b'PC Cleaner' in page, status
            status, _, script = get(port, '/app.js', cookie)
            assert status == 200 and b'renderCleaner' in script, status
            version = json.loads(get(port, '/health')[2])['version']
            # The installer stops the app this way before upgrades and uninstalls.
            assert subprocess.run([str(EXE), '--quit'], env=env, timeout=60).returncode == 0, 'quit failed'
            print('Packaged app OK:', version)
        finally:
            subprocess.run(['taskkill', '/PID', str(instance['pid']), '/F'], capture_output=True)
            time.sleep(1)


if __name__ == '__main__':
    main()
